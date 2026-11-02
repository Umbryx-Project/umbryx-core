import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import AttackPathNodeEditor from './NodeEditor.jsx';
import { api } from '../../api.js';

vi.mock('../../api.js', () => ({
  api: {
    listAttackPathNodes: vi.fn(),
    listAttackPathEdges: vi.fn(),
    listAttackPathBranches: vi.fn(),
    createAttackPathEdge: vi.fn(),
    updateAttackPathNode: vi.fn(),
    createAttackPathNode: vi.fn(),
    deleteAttackPathNode: vi.fn(),
    deleteAttackPathEdge: vi.fn(),
    createAttackPathBranch: vi.fn(),
    deleteAttackPathBranch: vi.fn(),
  },
}));

const toastError = vi.fn();
vi.mock('../../components/Toast.jsx', () => ({ toastError: (...a) => toastError(...a) }));
vi.mock('../../components/Confirm.jsx', () => ({ uiConfirm: vi.fn().mockResolvedValue(true) }));

const NODES = [
  { id: 'n1', node_type: 'entry', label: 'Entry', position_x: 0, position_y: 0, branch_name: '' },
  { id: 'n2', node_type: 'action', label: 'Do', position_x: 200, position_y: 0, branch_name: '' },
];

beforeEach(() => {
  vi.clearAllMocks();
  api.listAttackPathNodes.mockResolvedValue({ items: NODES });
  api.listAttackPathEdges.mockResolvedValue({ items: [] });
  api.listAttackPathBranches.mockResolvedValue({ items: [] });
  // дефолт: любая мутация успешна — тесты, проверяющие отказ,
  // перекрывают impl точечно. Без этого мок без impl возвращает
  // undefined и .then() в компоненте падает ВНЕ теста.
  api.createAttackPathEdge.mockResolvedValue({ id: 'e1' });
  api.updateAttackPathNode.mockResolvedValue({ id: 'n1' });
  api.createAttackPathNode.mockResolvedValue({ id: 'n3' });
  api.deleteAttackPathNode.mockResolvedValue({ ok: true });
  api.deleteAttackPathEdge.mockResolvedValue({ ok: true });
  api.createAttackPathBranch.mockResolvedValue({ id: 'b1' });
  api.deleteAttackPathBranch.mockResolvedValue({ ok: true });
});

async function open() {
  render(<AttackPathNodeEditor pathId="path1" accent="#15bbb1" />);
  await screen.findAllByText('Entry'); // ноды загрузились
  return screen;
}

// «Entry» встречается дважды (лейбл типа + имя узла) — mousedown по любому
// всплывает до div'а узла с обработчиком
function nodeEl(s, name) {
  return s.getAllByText(name)[0];
}

describe('AttackPathNodeEditor — failed mutations surface a toast', () => {
  it('edge creation failure → toast, no silent drop', async () => {
    const s = await open();
    api.createAttackPathEdge.mockRejectedValue(new Error('boom'));
    fireEvent.mouseDown(nodeEl(s, 'Entry'), { button: 0 }); // select
    fireEvent.click(s.getByText('Connect')); // режим соединения
    fireEvent.mouseDown(nodeEl(s, 'Do'), { button: 0 }); // цель → createAttackPathEdge
    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith(expect.stringContaining('Edge not created')));
  });

  it('node deletion failure → toast', async () => {
    const s = await open();
    api.deleteAttackPathNode.mockRejectedValue(new Error('boom'));
    fireEvent.mouseDown(nodeEl(s, 'Entry'), { button: 0 }); // select
    fireEvent.click(s.getByText('Delete')); // кнопка тулбара при выбранном узле
    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith(expect.stringContaining('Node not deleted')));
  });

  it('node save failure → toast (non-Error rejection covers the || e fallback)', async () => {
    const s = await open();
    api.updateAttackPathNode.mockRejectedValue('boom-string');
    fireEvent.mouseDown(nodeEl(s, 'Entry'), { button: 0 }); // select
    fireEvent.click(s.getByText('Edit')); // открывает модалку редактора
    const save = await s.findByText('Save'); // кнопка в модалке
    fireEvent.click(save);
    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith(expect.stringContaining('not saved')));
  });
});

describe('AttackPathNodeEditor — successful mutations run the load path', () => {
  // Happy-path companions to the toast tests above: the .then(load)
  // callbacks were the uncovered half of every kept handler.
  it('edge create success reloads the list', async () => {
    const s = await open();
    const loadsBefore = api.listAttackPathNodes.mock.calls.length;
    fireEvent.mouseDown(nodeEl(s, 'Entry'), { button: 0 });
    fireEvent.click(s.getByText('Connect'));
    fireEvent.mouseDown(nodeEl(s, 'Do'), { button: 0 });
    await waitFor(() => expect(api.createAttackPathEdge).toHaveBeenCalled());
    await waitFor(() =>
      expect(api.listAttackPathNodes.mock.calls.length).toBeGreaterThan(loadsBefore));
  });

  it('node save (update) success reloads and closes the editor', async () => {
    const s = await open();
    fireEvent.mouseDown(nodeEl(s, 'Entry'), { button: 0 });
    fireEvent.click(s.getByText('Edit'));
    const save = await s.findByText('Save');
    fireEvent.click(save);
    await waitFor(() => expect(api.updateAttackPathNode).toHaveBeenCalled());
    await waitFor(() => expect(s.queryByText('Save')).toBeNull());
  });

  it('canvas double-click creates a node and reloads', async () => {
    const s = await open();
    const loadsBefore = api.listAttackPathNodes.mock.calls.length;
    const canvas = document.querySelector('div[style*="radial-gradient"]'); // dotted canvas div
    fireEvent.dblClick(canvas);
    await waitFor(() => expect(api.createAttackPathNode).toHaveBeenCalled());
    await waitFor(() =>
      expect(api.listAttackPathNodes.mock.calls.length).toBeGreaterThan(loadsBefore));
  });

  it('node drag release persists the position', async () => {
    const s = await open();
    fireEvent.mouseDown(nodeEl(s, 'Entry'), { button: 0 });
    fireEvent.mouseMove(window, { clientX: 60, clientY: 40 });
    fireEvent.mouseUp(window);
    await waitFor(() => expect(api.updateAttackPathNode).toHaveBeenCalledWith(
      'n1', expect.objectContaining({ position_x: expect.any(Number), position_y: expect.any(Number) })));
  });
});
