import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { JSMHelpCenterSearch } from '../JSMHelpCenterSearch.improved';

describe('JSMHelpCenterSearch', () => {
  const mockOnSearch = jest.fn();
  const mockOnClear = jest.fn();
  const mockOnFocus = jest.fn();
  const mockOnBlur = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders with default props', () => {
    render(<JSMHelpCenterSearch onSearch={mockOnSearch} />);
    
    const input = screen.getByRole('searchbox');
    expect(input).toBeInTheDocument();
    expect(input).toHaveAttribute('placeholder', 'Search help articles...');
  });

  it('handles basic text input', async () => {
    const user = userEvent.setup();
    render(<JSMHelpCenterSearch onSearch={mockOnSearch} debounceMs={100} />);
    
    const input = screen.getByRole('searchbox');
    await user.type(input, 'test query');
    
    expect(input).toHaveValue('test query');
    
    // Wait for debounced search
    await waitFor(() => {
      expect(mockOnSearch).toHaveBeenCalledWith('test query');
    }, { timeout: 200 });
  });

  it('handles Japanese IME composition correctly', async () => {
    render(<JSMHelpCenterSearch onSearch={mockOnSearch} debounceMs={100} />);
    
    const input = screen.getByRole('searchbox');
    
    // Simulate Japanese IME composition
    fireEvent.compositionStart(input);
    fireEvent.change(input, { target: { value: 'こんにちは' } });
    
    // During composition, search should not be triggered
    await new Promise(resolve => setTimeout(resolve, 150));
    expect(mockOnSearch).not.toHaveBeenCalled();
    
    // End composition
    fireEvent.compositionEnd(input, { target: { value: 'こんにちは' } });
    
    // Now search should be triggered
    await waitFor(() => {
      expect(mockOnSearch).toHaveBeenCalledWith('こんにちは');
    }, { timeout: 200 });
  });

  it('shows clear button when there is text', async () => {
    const user = userEvent.setup();
    render(<JSMHelpCenterSearch onSearch={mockOnSearch} onClear={mockOnClear} />);
    
    const input = screen.getByRole('searchbox');
    await user.type(input, 'test');
    
    const clearButton = screen.getByTestId('clear-button');
    expect(clearButton).toBeInTheDocument();
    
    await user.click(clearButton);
    expect(input).toHaveValue('');
    expect(mockOnClear).toHaveBeenCalled();
  });

  it('handles focus and blur events', async () => {
    const user = userEvent.setup();
    render(
      <JSMHelpCenterSearch 
        onSearch={mockOnSearch} 
        onFocus={mockOnFocus}
        onBlur={mockOnBlur}
      />
    );
    
    const input = screen.getByRole('searchbox');
    
    await user.click(input);
    expect(mockOnFocus).toHaveBeenCalled();
    
    await user.tab();
    expect(mockOnBlur).toHaveBeenCalled();
  });

  it('handles escape key to clear input', async () => {
    const user = userEvent.setup();
    render(<JSMHelpCenterSearch onSearch={mockOnSearch} />);
    
    const input = screen.getByRole('searchbox');
    await user.type(input, 'test');
    expect(input).toHaveValue('test');
    
    await user.keyboard('{Escape}');
    expect(input).toHaveValue('');
  });

  it('respects maxLength prop', async () => {
    const user = userEvent.setup();
    render(<JSMHelpCenterSearch onSearch={mockOnSearch} maxLength={5} />);
    
    const input = screen.getByRole('searchbox');
    await user.type(input, 'this is a very long text');
    
    // Should be truncated to maxLength
    expect(input.value.length).toBeLessThanOrEqual(5);
  });

  it('handles form submission', async () => {
    const user = userEvent.setup();
    render(<JSMHelpCenterSearch onSearch={mockOnSearch} />);
    
    const input = screen.getByRole('searchbox');
    await user.type(input, 'test query');
    await user.keyboard('{Enter}');
    
    expect(mockOnSearch).toHaveBeenCalledWith('test query');
  });

  it('prevents form submission during IME composition', () => {
    render(<JSMHelpCenterSearch onSearch={mockOnSearch} />);
    
    const input = screen.getByRole('searchbox');
    
    // Start composition
    fireEvent.compositionStart(input);
    fireEvent.change(input, { target: { value: 'こんに' } });
    
    // Try to submit during composition
    fireEvent.keyDown(input, { key: 'Enter' });
    
    // Search should not be called during composition
    expect(mockOnSearch).not.toHaveBeenCalled();
  });

  it('applies custom className', () => {
    render(<JSMHelpCenterSearch onSearch={mockOnSearch} className="custom-class" />);
    
    const container = screen.getByTestId('search-wrapper').parentElement;
    expect(container).toHaveClass('custom-class');
  });

  it('disables input when disabled prop is true', () => {
    render(<JSMHelpCenterSearch onSearch={mockOnSearch} disabled />);
    
    const input = screen.getByRole('searchbox');
    expect(input).toBeDisabled();
  });

  it('auto-focuses when autoFocus prop is true', () => {
    render(<JSMHelpCenterSearch onSearch={mockOnSearch} autoFocus />);
    
    const input = screen.getByRole('searchbox');
    expect(input).toHaveFocus();
  });

  it('has proper accessibility attributes', () => {
    render(<JSMHelpCenterSearch onSearch={mockOnSearch} />);
    
    const input = screen.getByRole('searchbox');
    expect(input).toHaveAttribute('aria-label', 'Search help articles');
    expect(input).toHaveAttribute('aria-describedby', 'search-help-text');
    
    const helpText = screen.getByText(/Use this search box to find help articles/);
    expect(helpText).toBeInTheDocument();
  });

  it('handles composition update events', () => {
    render(<JSMHelpCenterSearch onSearch={mockOnSearch} />);
    
    const input = screen.getByRole('searchbox');
    
    fireEvent.compositionStart(input);
    fireEvent.compositionUpdate(input, { target: { value: 'こん' } });
    fireEvent.compositionUpdate(input, { target: { value: 'こんに' } });
    fireEvent.compositionEnd(input, { target: { value: 'こんにちは' } });
    
    expect(input).toHaveValue('こんにちは');
  });
});