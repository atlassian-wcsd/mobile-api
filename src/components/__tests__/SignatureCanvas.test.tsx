import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import { SignatureCanvas } from '../SignatureCanvas';
import { Signature } from '../../models/Signature';

// Mock crypto.randomUUID
Object.defineProperty(global, 'crypto', {
  value: {
    randomUUID: jest.fn(() => 'test-uuid-123'),
  },
});

// Mock canvas context
const mockContext = {
  lineWidth: 2,
  lineCap: 'round',
  lineJoin: 'round',
  strokeStyle: '#000000',
  beginPath: jest.fn(),
  moveTo: jest.fn(),
  lineTo: jest.fn(),
  stroke: jest.fn(),
  closePath: jest.fn(),
  clearRect: jest.fn(),
};

const mockCanvas = {
  getContext: jest.fn(() => mockContext),
  toDataURL: jest.fn(() => 'data:image/png;base64,mockImageData'),
  getBoundingClientRect: jest.fn(() => ({
    left: 10,
    top: 20,
    width: 500,
    height: 200,
  })),
  width: 500,
  height: 200,
};

// Mock HTMLCanvasElement
HTMLCanvasElement.prototype.getContext = jest.fn(() => mockContext);
HTMLCanvasElement.prototype.toDataURL = jest.fn(() => 'data:image/png;base64,mockImageData');
HTMLCanvasElement.prototype.getBoundingClientRect = jest.fn(() => ({
  left: 10,
  top: 20,
  width: 500,
  height: 200,
}));

describe('SignatureCanvas', () => {
  const mockOnSave = jest.fn();
  const mockOnClear = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    mockContext.beginPath.mockClear();
    mockContext.moveTo.mockClear();
    mockContext.lineTo.mockClear();
    mockContext.stroke.mockClear();
    mockContext.closePath.mockClear();
    mockContext.clearRect.mockClear();
  });

  it('renders canvas with default dimensions', () => {
    render(<SignatureCanvas />);

    const canvas = screen.getByRole('img', { hidden: true }); // Canvas has img role
    expect(canvas).toBeInTheDocument();
    expect(canvas).toHaveAttribute('width', '500');
    expect(canvas).toHaveAttribute('height', '200');
  });

  it('renders canvas with custom dimensions', () => {
    render(<SignatureCanvas width={800} height={300} />);

    const canvas = screen.getByRole('img', { hidden: true });
    expect(canvas).toHaveAttribute('width', '800');
    expect(canvas).toHaveAttribute('height', '300');
  });

  it('renders clear and save buttons', () => {
    render(<SignatureCanvas />);

    expect(screen.getByText('Clear')).toBeInTheDocument();
    expect(screen.getByText('Save Signature')).toBeInTheDocument();
  });

  it('applies custom className', () => {
    render(<SignatureCanvas className="custom-signature-canvas" />);

    const container = screen.getByText('Clear').parentElement?.parentElement;
    expect(container).toHaveClass('custom-signature-canvas');
  });

  it('initializes canvas context with correct properties', () => {
    render(<SignatureCanvas />);

    expect(mockContext.lineWidth).toBe(2);
    expect(mockContext.lineCap).toBe('round');
    expect(mockContext.lineJoin).toBe('round');
    expect(mockContext.strokeStyle).toBe('#000000');
  });

  it('handles mouse drawing events', () => {
    render(<SignatureCanvas />);

    const canvas = screen.getByRole('img', { hidden: true });

    // Start drawing
    fireEvent.mouseDown(canvas, {
      nativeEvent: { offsetX: 100, offsetY: 50 },
    });

    expect(mockContext.beginPath).toHaveBeenCalled();
    expect(mockContext.moveTo).toHaveBeenCalledWith(100, 50);

    // Continue drawing
    fireEvent.mouseMove(canvas, {
      nativeEvent: { offsetX: 120, offsetY: 60 },
    });

    expect(mockContext.lineTo).toHaveBeenCalledWith(120, 60);
    expect(mockContext.stroke).toHaveBeenCalled();

    // Stop drawing
    fireEvent.mouseUp(canvas);

    expect(mockContext.closePath).toHaveBeenCalled();
  });

  it('handles touch drawing events', () => {
    render(<SignatureCanvas />);

    const canvas = screen.getByRole('img', { hidden: true });

    // Mock touch event
    const touchEvent = {
      touches: [{ clientX: 110, clientY: 70 }],
    };

    // Start drawing with touch
    fireEvent.touchStart(canvas, touchEvent);

    expect(mockContext.beginPath).toHaveBeenCalled();
    expect(mockContext.moveTo).toHaveBeenCalledWith(100, 50); // 110-10, 70-20 (accounting for getBoundingClientRect)

    // Continue drawing with touch
    const touchMoveEvent = {
      touches: [{ clientX: 130, clientY: 80 }],
      preventDefault: jest.fn(),
    };

    fireEvent.touchMove(canvas, touchMoveEvent);

    expect(touchMoveEvent.preventDefault).toHaveBeenCalled();
    expect(mockContext.lineTo).toHaveBeenCalledWith(120, 60);
    expect(mockContext.stroke).toHaveBeenCalled();

    // Stop drawing with touch
    fireEvent.touchEnd(canvas);

    expect(mockContext.closePath).toHaveBeenCalled();
  });

  it('does not draw when mouse moves without being pressed', () => {
    render(<SignatureCanvas />);

    const canvas = screen.getByRole('img', { hidden: true });

    // Move mouse without pressing
    fireEvent.mouseMove(canvas, {
      nativeEvent: { offsetX: 120, offsetY: 60 },
    });

    expect(mockContext.lineTo).not.toHaveBeenCalled();
    expect(mockContext.stroke).not.toHaveBeenCalled();
  });

  it('stops drawing when mouse leaves canvas', () => {
    render(<SignatureCanvas />);

    const canvas = screen.getByRole('img', { hidden: true });

    // Start drawing
    fireEvent.mouseDown(canvas, {
      nativeEvent: { offsetX: 100, offsetY: 50 },
    });

    // Leave canvas
    fireEvent.mouseLeave(canvas);

    expect(mockContext.closePath).toHaveBeenCalled();

    // Moving mouse after leaving should not draw
    fireEvent.mouseMove(canvas, {
      nativeEvent: { offsetX: 120, offsetY: 60 },
    });

    expect(mockContext.lineTo).not.toHaveBeenCalled();
  });

  it('clears canvas when clear button is clicked', () => {
    render(<SignatureCanvas onClear={mockOnClear} />);

    const clearButton = screen.getByText('Clear');
    fireEvent.click(clearButton);

    expect(mockContext.clearRect).toHaveBeenCalledWith(0, 0, 500, 200);
    expect(mockOnClear).toHaveBeenCalled();
  });

  it('saves signature when save button is clicked', () => {
    const mockDate = new Date('2024-01-01T12:00:00Z');
    jest.spyOn(global, 'Date').mockImplementation(() => mockDate as any);

    render(<SignatureCanvas onSave={mockOnSave} width={800} height={300} />);

    const saveButton = screen.getByText('Save Signature');
    fireEvent.click(saveButton);

    const expectedSignature: Signature = {
      id: 'test-uuid-123',
      imageData: 'data:image/png;base64,mockImageData',
      width: 800,
      height: 300,
      createdAt: mockDate,
      userId: 'current-user-id',
      metadata: {
        device: 'browser',
        platform: navigator.userAgent,
        pressureData: [],
      },
    };

    expect(mockOnSave).toHaveBeenCalledWith(expectedSignature);

    // Restore Date
    (global.Date as any).mockRestore();
  });

  it('handles canvas context not available', () => {
    // Mock getContext to return null
    HTMLCanvasElement.prototype.getContext = jest.fn(() => null);

    render(<SignatureCanvas />);

    const canvas = screen.getByRole('img', { hidden: true });

    // Try to draw - should not throw error
    fireEvent.mouseDown(canvas, {
      nativeEvent: { offsetX: 100, offsetY: 50 },
    });

    // Should not call any context methods
    expect(mockContext.beginPath).not.toHaveBeenCalled();

    // Restore original mock
    HTMLCanvasElement.prototype.getContext = jest.fn(() => mockContext);
  });

  it('handles canvas ref not available for save', () => {
    // Mock useRef to return null
    const originalUseRef = React.useRef;
    React.useRef = jest.fn(() => ({ current: null }));

    render(<SignatureCanvas onSave={mockOnSave} />);

    const saveButton = screen.getByText('Save Signature');
    fireEvent.click(saveButton);

    // Should not call onSave when canvas ref is null
    expect(mockOnSave).not.toHaveBeenCalled();

    // Restore useRef
    React.useRef = originalUseRef;
  });

  it('handles canvas ref not available for clear', () => {
    // Mock useRef to return null
    const originalUseRef = React.useRef;
    React.useRef = jest.fn(() => ({ current: null }));

    render(<SignatureCanvas onClear={mockOnClear} />);

    const clearButton = screen.getByText('Clear');
    fireEvent.click(clearButton);

    // Should not call onClear when canvas ref is null
    expect(mockOnClear).not.toHaveBeenCalled();

    // Restore useRef
    React.useRef = originalUseRef;
  });

  it('handles touch events with no touches', () => {
    render(<SignatureCanvas />);

    const canvas = screen.getByRole('img', { hidden: true });

    // Mock touch event with no touches
    const touchEvent = {
      touches: [],
    };

    fireEvent.touchStart(canvas, touchEvent);

    // Should use default coordinates (0, 0)
    expect(mockContext.moveTo).toHaveBeenCalledWith(0, 0);
  });
});