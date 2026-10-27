import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Select } from './UI.jsx';

// Regression: the dropdown listbox is portaled to <body>; the outside-click
// guard used to check only the anchor, so a real mousedown-then-click on an
// option closed the list before the click landed and selection never fired.
describe('Select (portaled listbox)', () => {
  it('selects an option on a real mousedown+click sequence', async () => {
    const onChange = vi.fn();
    render(<Select value="viewer" onChange={onChange} options={[{ value: 'viewer', label: 'Viewer' }, { value: 'analyst', label: 'Analyst' }]} />);

    fireEvent.click(screen.getByRole('combobox'));
    const option = await waitFor(() => screen.getByRole('option', { name: 'Analyst' }));

    fireEvent.mouseDown(option);   // must NOT be treated as an outside click
    fireEvent.click(option);       // selection happens after the guard

    expect(onChange).toHaveBeenCalledWith('analyst');
  });
});
