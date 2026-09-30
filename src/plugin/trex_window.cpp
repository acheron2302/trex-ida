// Qt types window for trexida.
//
// Compiled only when CMake found a `QT_NAMESPACE=QT` Qt matching the target IDA (TREX_HAVE_QT=1).
// The Qt-less build links no trex_window.cpp at all; plugin.cpp ships no-op stubs in that case.
//
// Layout:
//   VBox:
//     HBox (rescan buttons on the left, copy/apply/export on the right with a stretch between)
//     QLabel status line
//     HSplitter:
//       QTreeWidget   (one row per reconstructed struct: Name | Kind | Size | Members)
//       QTextEdit     (read-only: declaration + "Variables of this type:" + per-function lines)
// One TrexTypesWindow instance is reused across rescan calls; selection by name survives an
// update so the user does not lose their place.

#include "trex_window.hpp"

#if TREX_HAVE_QT

// C++/STL FIRST (mirror plugin.cpp:11): the IDA SDK shadows C library names used by the STL.
#include <algorithm>
#include <cstdio>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <kernwin.hpp>
#include <ida.hpp>

#include <QtWidgets>

// ---------------------------------------------------------------------------
// Module state: one window instance, one widget, one event listener.

namespace
{

constexpr const char *kWidgetCaption = "TRex types";

struct TrexTypesWindow : public QT::QWidget
{
  QT::QTreeWidget *tree = nullptr;
  QT::QTextEdit   *detail = nullptr;
  QT::QLabel      *status = nullptr;
  trex::ui::WindowCallbacks cbs;

  explicit TrexTypesWindow(QT::QWidget *parent)
    : QT::QWidget(parent)
  {
    auto *root = new QT::QVBoxLayout(this);
    root->setContentsMargins(6, 6, 6, 6);
    root->setSpacing(4);

    // ----- button rows: rescan group | stretch | copy/apply/export group
    auto *buttons = new QT::QHBoxLayout();
    buttons->setSpacing(4);

    auto *rescan_deep = new QT::QPushButton(QT::QString::fromUtf8("Rescan (function + call tree)"), this);
    auto *rescan_all  = new QT::QPushButton(QT::QString::fromUtf8("Rescan all"), this);
    auto *copy_one    = new QT::QPushButton(QT::QString::fromUtf8("Copy struct"), this);
    auto *copy_all    = new QT::QPushButton(QT::QString::fromUtf8("Copy all"), this);
    auto *apply_btn   = new QT::QPushButton(QT::QString::fromUtf8("Apply to database"), this);
    auto *export_btn  = new QT::QPushButton(QT::QString::fromUtf8("Export files"), this);

    buttons->addWidget(rescan_deep);
    buttons->addWidget(rescan_all);
    buttons->addStretch(1);
    buttons->addWidget(copy_one);
    buttons->addWidget(copy_all);
    buttons->addWidget(apply_btn);
    buttons->addWidget(export_btn);

    root->addLayout(buttons);

    // ----- status
    status = new QT::QLabel(this);
    status->setText(QT::QString::fromUtf8("No reconstruction yet - use a Rescan button"));
    root->addWidget(status);

    // ----- tree + detail
    auto *split = new QT::QSplitter(QT::Qt::Horizontal, this);
    tree = new QT::QTreeWidget(split);
    tree->setColumnCount(4);
    tree->setHeaderLabels(
      QT::QStringList()
        << QT::QString::fromUtf8("Name")
        << QT::QString::fromUtf8("Kind")
        << QT::QString::fromUtf8("Size")
        << QT::QString::fromUtf8("Members"));
    tree->setRootIsDecorated(false);
    tree->setUniformRowHeights(true);
    tree->setSelectionMode(QT::QAbstractItemView::SingleSelection);
    tree->setSortingEnabled(false);

    detail = new QT::QTextEdit(split);
    detail->setReadOnly(true);
    detail->setLineWrapMode(QT::QTextEdit::NoWrap);

    split->addWidget(tree);
    split->addWidget(detail);
    split->setStretchFactor(0, 1);
    split->setStretchFactor(1, 2);
    split->setSizes({ 280, 560 });
    root->addWidget(split, 1);

    // ----- signal wiring
    QT::QObject::connect(tree, &QT::QTreeWidget::currentItemChanged,
                         this, &TrexTypesWindow::on_selection_changed);
    QT::QObject::connect(copy_one, &QT::QPushButton::clicked,
                         this, &TrexTypesWindow::on_copy_one);
    QT::QObject::connect(copy_all, &QT::QPushButton::clicked,
                         this, &TrexTypesWindow::on_copy_all);
    QT::QObject::connect(apply_btn, &QT::QPushButton::clicked,
                         this, &TrexTypesWindow::on_apply);
    QT::QObject::connect(export_btn, &QT::QPushButton::clicked,
                         this, &TrexTypesWindow::on_export);
    QT::QObject::connect(rescan_deep, &QT::QPushButton::clicked,
                         this, &TrexTypesWindow::on_rescan_deep);
    QT::QObject::connect(rescan_all, &QT::QPushButton::clicked,
                         this, &TrexTypesWindow::on_rescan_all);
  }

  // The tree stores the struct name in each QTreeWidgetItem's UserRole so selection survives a
  // repopulate even when rows reorder.
  void repopulate(const trex::ui::WindowModel &model)
  {
    // Remember the selection by name; the row index can change across rescan runs.
    QString selected;
    if (auto *it = tree->currentItem())
      selected = it->data(0, QT::Qt::UserRole).toString();

    tree->clear();

    QT::QTreeWidgetItem *first = nullptr;
    QT::QTreeWidgetItem *to_select = nullptr;
    for (const trex::ui::StructInfo &s : model.structs)
    {
      auto *item = new QT::QTreeWidgetItem(tree);
      item->setText(0, QT::QString::fromUtf8(s.name.c_str()));
      item->setText(1, QT::QString::fromUtf8(s.kind.c_str()));
      if (s.size.has_value())
        item->setText(2, QT::QString::number(static_cast<qlonglong>(*s.size)));
      else
        item->setText(2, QT::QString::fromUtf8("?"));
      item->setText(3, QT::QString::number(static_cast<qlonglong>(s.member_count)));
      item->setData(0, QT::Qt::UserRole, QT::QString::fromUtf8(s.name.c_str()));
      if (first == nullptr)
        first = item;
      if (!selected.isEmpty() && selected == item->data(0, QT::Qt::UserRole))
        to_select = item;
    }

    if (to_select != nullptr)
      tree->setCurrentItem(to_select);
    else if (first != nullptr)
      tree->setCurrentItem(first);
    else
      detail->clear();

    update_status(model);
  }

  void update_status(const trex::ui::WindowModel &model)
  {
    if (model.structs.empty())
    {
      status->setText(QT::QString::fromUtf8("No reconstruction yet - use a Rescan button"));
      return;
    }
    status->setText(QT::QString::fromUtf8("%1 struct(s) \xc2\xb7 %2 variable use(s)")
                      .arg(static_cast<int>(model.structs.size()))
                      .arg(static_cast<int>(model.uses.size())));
  }

  void on_selection_changed(QT::QTreeWidgetItem *cur, QT::QTreeWidgetItem * /*prev*/)
  {
    if (cur == nullptr)
    {
      detail->clear();
      return;
    }
    const std::string name = cur->data(0, QT::Qt::UserRole).toString().toStdString();

    // We do not keep the model on the widget (the update() path replaces it), so read the
    // freshest struct declaration by name from the last-set model. cbs carries nothing here -
    // we use a side channel stored as a dynamic property on the item.
    const std::string decl = cur->data(0, QT::Qt::UserRole + 1).toString().toStdString();
    const std::string kind = cur->text(1).toStdString();

    std::string text;
    text += decl;
    if (!text.empty() && text.back() != '\n')
      text += "\n";

    // Variable uses: the WindowModel passed to update_types_window sets these as a property
    // on the item under UserRole+2 (a newline-joined "<func> :: <lvar> @ <ea>" string).
    const QString joined = cur->data(0, QT::Qt::UserRole + 2).toString();
    text += "\nVariables of this type:\n";
    if (joined.isEmpty())
      text += "  (none recorded for this reconstruction)\n";
    else
      text += joined.toStdString();

    detail->setPlainText(text);
    (void)name;
    (void)kind;
  }

  void on_copy_one()
  {
    auto *cur = tree->currentItem();
    if (cur == nullptr)
      return;
    const QString text = cur->data(0, QT::Qt::UserRole + 1).toString();
    if (text.isEmpty())
      return;
    QT::QApplication::clipboard()->setText(text);
    status->setText(QT::QString::fromUtf8("Copied %1")
                      .arg(cur->text(0)));
  }

  void on_copy_all()
  {
    QStringList parts;
    for (int i = 0; i < tree->topLevelItemCount(); ++i)
    {
      auto *it = tree->topLevelItem(i);
      const QString text = it->data(0, QT::Qt::UserRole + 1).toString();
      if (!text.isEmpty())
        parts.append(text);
    }
    if (parts.isEmpty())
      return;
    QT::QApplication::clipboard()->setText(parts.join(QT::QString::fromUtf8("\n\n")));
    status->setText(QT::QString::fromUtf8("Copied %1 struct(s) to clipboard")
                      .arg(parts.size()));
  }

  void on_apply()    { if (cbs.apply)    cbs.apply(); }
  void on_export()   { if (cbs.export_files) cbs.export_files(); }
  void on_rescan_deep() { if (cbs.rescan_current_deep) cbs.rescan_current_deep(); }
  void on_rescan_all()  { if (cbs.rescan_all) cbs.rescan_all(); }
};

TrexTypesWindow *g_window = nullptr; ///< owned via Qt parent (the IDA TWidget -> QWidget).

// We need to recover the model across `ui_widget_visible` -> repopulate, so the freshly-built
// QWidget gets the model and callbacks on first show. Stored here between show() and
// ui_widget_visible.
struct Pending
{
  trex::ui::WindowModel model;
  trex::ui::WindowCallbacks cbs;
};
Pending *g_pending = nullptr;

// IDA event listener: when our empty widget becomes visible, parent our QWidget into it. When
// it goes invisible, drop the reference (the widget itself is owned by IDA's framework).
struct WidgetListener : public event_listener_t
{
  TWidget *widget = nullptr;

  WidgetListener(TWidget *w) : widget(w) {}

  ssize_t idaapi on_event(ssize_t code, va_list va) override
  {
    if (code == ui_widget_visible)
    {
      TWidget *w = va_arg(va, TWidget *);
      if (w == widget && g_pending != nullptr && g_window == nullptr)
      {
        g_window = new TrexTypesWindow(reinterpret_cast<QT::QWidget *>(widget));
        g_window->cbs = g_pending->cbs;
        g_window->repopulate(g_pending->model);
        g_pending = nullptr;
      }
    }
    else if (code == ui_widget_invisible)
    {
      TWidget *w = va_arg(va, TWidget *);
      if (w == widget)
      {
        g_window = nullptr;
      }
    }
    return 0;
  }
};

WidgetListener *g_listener = nullptr;

} // namespace

namespace trex::ui
{

bool qt_available() { return true; }

void show_types_window(const WindowModel &model, const WindowCallbacks &cbs)
{
  // Close any prior window first so we always open a fresh one with the latest model.
  TWidget *existing = find_widget(kWidgetCaption);
  if (existing != nullptr)
    close_widget(existing, WCLS_SAVE);

  // Local Pending on the stack would dangle the moment this function returns; the WidgetListener
  // callback fires from a different event-loop cycle and dereferences g_pending. Heap-allocate.
  auto *p = new Pending;
  p->model = model;
  p->cbs = cbs;
  g_pending = p;

  TWidget *w = create_empty_widget(kWidgetCaption);
  if (w == nullptr)
  {
    delete g_pending;
    g_pending = nullptr;
    msg("[trexida] could not create types window\n");
    return;
  }
  display_widget(w, WOPN_DP_TAB | WOPN_RESTORE);

  g_listener = new WidgetListener(w);
  hook_event_listener(HT_UI, g_listener);
  // The listener will install the QWidget when ui_widget_visible fires.
}

void update_types_window(const WindowModel &model)
{
  if (g_window == nullptr)
    return;
  // Store per-row decl + per-row uses list on each QTreeWidgetItem so the selection-changed
  // handler can rebuild the detail pane. The detail build itself is wired off UserRole+1/+2.
  std::map<std::string, std::vector<std::string>> uses_by_type;
  for (const auto &u : model.uses)
    uses_by_type[u.type_name].push_back(u.func + " :: " + u.lvar + " @ " + u.ea_hex);

  // The tree already exists; clear and rebuild. Preserve selection by name.
  QString selected;
  if (auto *cur = g_window->tree->currentItem())
    selected = cur->data(0, QT::Qt::UserRole).toString();

  g_window->tree->clear();

  QT::QTreeWidgetItem *first = nullptr;
  QT::QTreeWidgetItem *to_select = nullptr;
  for (const StructInfo &s : model.structs)
  {
    auto *item = new QT::QTreeWidgetItem(g_window->tree);
    item->setText(0, QT::QString::fromUtf8(s.name.c_str()));
    item->setText(1, QT::QString::fromUtf8(s.kind.c_str()));
    if (s.size.has_value())
      item->setText(2, QT::QString::number(static_cast<qlonglong>(*s.size)));
    else
      item->setText(2, QT::QString::fromUtf8("?"));
    item->setText(3, QT::QString::number(static_cast<qlonglong>(s.member_count)));
    item->setData(0, QT::Qt::UserRole, QT::QString::fromUtf8(s.name.c_str()));
    item->setData(0, QT::Qt::UserRole + 1, QT::QString::fromUtf8(s.declaration.c_str()));

    QString joined;
    auto it = uses_by_type.find(s.name);
    if (it != uses_by_type.end())
    {
      QStringList lines;
      for (const auto &line : it->second)
        lines.append(QT::QString::fromUtf8(line.c_str()));
      joined = lines.join(QT::QChar('\n'));
    }
    item->setData(0, QT::Qt::UserRole + 2, joined);

    if (first == nullptr)
      first = item;
    if (!selected.isEmpty() && selected == item->data(0, QT::Qt::UserRole))
      to_select = item;
  }

  if (to_select != nullptr)
    g_window->tree->setCurrentItem(to_select);
  else if (first != nullptr)
    g_window->tree->setCurrentItem(first);
  else
    g_window->detail->clear();

  g_window->update_status(model);
}

} // namespace trex::ui

#endif // TREX_HAVE_QT