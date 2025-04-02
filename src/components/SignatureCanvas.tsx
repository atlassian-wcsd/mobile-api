import React, { useRef, useEffect, useState } from 'react';
import { Signature } from '../models/Signature';

interface SignatureCanvasProps {
  width?: number;
  height?: number;
  onSave?: (signature: Signature) => void;
  onClear?: () => void;
  className?: string;
}

interface Point {
  x: number;
  y: number;
  pressure: number;
}

export const SignatureCanvas: React.FC<SignatureCanvasProps> = ({
  width = 500,
  height = 200,
  onSave,
  onClear,
  className,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [isDrawing, setIsDrawing] = useState(false);
  const [context, setContext] = useState<CanvasRenderingContext2D | null>(null);
  const [pressurePoints, setPressurePoints] = useState<Point[]>([]);
  const [lastPoint, setLastPoint] = useState<Point | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set up canvas with higher quality settings
    ctx.lineWidth = 2;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.strokeStyle = '#000000';
    
    // Enable pressure sensitivity if supported
    if ((canvas as any).getContext('2d').getContextAttributes?.()?.desynchronized) {
      (canvas as any).getContext('2d', { desynchronized: true });
    }
    
    setContext(ctx);

    // Handle screen DPI scaling
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.scale(dpr, dpr);
  }, [width, height]);

  const startDrawing = (e: React.PointerEvent) => {
    setIsDrawing(true);
    const { x, y, pressure } = getPointerData(e);
    const newPoint = { x, y, pressure };
    setLastPoint(newPoint);
    context?.beginPath();
    context?.moveTo(x, y);
    setPressurePoints([newPoint]);
  };

  const draw = (e: React.PointerEvent) => {
    if (!isDrawing || !context || !lastPoint) return;
    e.preventDefault();
    
    const { x, y, pressure } = getPointerData(e);
    const newPoint = { x, y, pressure };
    
    // Smooth line drawing with pressure sensitivity
    const lineWidth = pressure * 4 + 1; // Scale pressure to reasonable line width
    context.lineWidth = lineWidth;
    
    // Quadratic curve for smoother lines
    context.beginPath();
    context.moveTo(lastPoint.x, lastPoint.y);
    context.quadraticCurveTo(
      lastPoint.x, lastPoint.y,
      (lastPoint.x + x) / 2,
      (lastPoint.y + y) / 2
    );
    context.stroke();
    
    setLastPoint(newPoint);
    setPressurePoints(prev => [...prev, newPoint]);
  };

  const stopDrawing = () => {
    setIsDrawing(false);
    setLastPoint(null);
    context?.closePath();
  };

  const getPointerData = (e: React.PointerEvent) => {
    const canvas = canvasRef.current;
    if (!canvas) return { x: 0, y: 0, pressure: 0.5 };

    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    // Default pressure to 0.5 if not supported
    const pressure = e.pressure || 0.5;

    return { x, y, pressure };
  };

  const clearCanvas = () => {
    if (!context || !canvasRef.current) return;
    context.clearRect(0, 0, width, height);
    setPressurePoints([]);
    onClear?.();
  };

  const saveSignature = () => {
    if (!canvasRef.current) return;

    const signature: Signature = {
      id: crypto.randomUUID(),
      imageData: canvasRef.current.toDataURL('image/png'),
      width,
      height,
      createdAt: new Date(),
      userId: 'current-user-id', // This should be replaced with actual user ID
      metadata: {
        device: 'mobile',
        platform: navigator.userAgent,
        pressureData: pressurePoints.map(point => point.pressure),
      },
    };

    onSave?.(signature);
  };

  return (
    <div className={className}>
      <canvas
        ref={canvasRef}
        style={{
          border: '1px solid #ccc',
          touchAction: 'none',
          backgroundColor: '#fff',
        }}
        onPointerDown={startDrawing}
        onPointerMove={draw}
        onPointerUp={stopDrawing}
        onPointerLeave={stopDrawing}
      />
      <div style={{ marginTop: '10px' }}>
        <button 
          onClick={clearCanvas}
          style={{
            padding: '8px 16px',
            marginRight: '10px',
            borderRadius: '4px',
            border: '1px solid #ccc',
          }}
        >
          Clear
        </button>
        <button 
          onClick={saveSignature}
          style={{
            padding: '8px 16px',
            borderRadius: '4px',
            backgroundColor: '#007bff',
            color: '#fff',
            border: 'none',
          }}
        >
          Save Signature
        </button>
      </div>
    </div>
  );
};

export default SignatureCanvas;