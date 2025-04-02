import React, { useRef, useEffect, useState } from 'react';
import { Signature } from '../models/Signature';
import SignatureCanvas from './SignatureCanvas';

interface MobileSignatureCanvasProps {
  width?: number;
  height?: number;
  onSave?: (signature: Signature) => void;
  onClear?: () => void;
  className?: string;
  enablePressure?: boolean;
  enableOrientation?: boolean;
}

export const MobileSignatureCanvas: React.FC<MobileSignatureCanvasProps> = ({
  width = 500,
  height = 200,
  onSave,
  onClear,
  className,
  enablePressure = true,
  enableOrientation = true,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [isDrawing, setIsDrawing] = useState(false);
  const [context, setContext] = useState<CanvasRenderingContext2D | null>(null);
  const [pressurePoints, setPressurePoints] = useState<number[]>([]);
  const [orientation, setOrientation] = useState<number | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Enhanced canvas setup for mobile
    ctx.lineWidth = 2;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.strokeStyle = '#000000';
    
    setContext(ctx);

    // Set up orientation detection
    if (enableOrientation) {
      const handleOrientation = (event: DeviceOrientationEvent) => {
        setOrientation(event.gamma || null); // gamma represents the left-to-right tilt
      };
      
      window.addEventListener('deviceorientation', handleOrientation);
      return () => window.removeEventListener('deviceorientation', handleOrientation);
    }
  }, [enableOrientation]);

  const startDrawing = (e: React.TouchEvent) => {
    setIsDrawing(true);
    const { offsetX, offsetY, pressure } = getCoordinates(e);
    
    if (context) {
      context.beginPath();
      context.moveTo(offsetX, offsetY);
      
      if (enablePressure && pressure !== undefined) {
        context.lineWidth = pressure * 4; // Adjust line width based on pressure
        setPressurePoints(prev => [...prev, pressure]);
      }
    }
  };

  const draw = (e: React.TouchEvent) => {
    if (!isDrawing || !context) return;
    e.preventDefault();
    
    const { offsetX, offsetY, pressure } = getCoordinates(e);
    
    if (enablePressure && pressure !== undefined) {
      context.lineWidth = pressure * 4;
      setPressurePoints(prev => [...prev, pressure]);
    }
    
    context.lineTo(offsetX, offsetY);
    context.stroke();
  };

  const stopDrawing = () => {
    setIsDrawing(false);
    context?.closePath();
  };

  const getCoordinates = (e: React.TouchEvent) => {
    const canvas = canvasRef.current;
    if (!canvas) return { offsetX: 0, offsetY: 0, pressure: 0 };

    const touch = e.touches[0];
    const rect = canvas.getBoundingClientRect();
    
    return {
      offsetX: touch.clientX - rect.left,
      offsetY: touch.clientY - rect.top,
      pressure: (touch as any).force || (touch as any).pressure || 0.5,
    };
  };

  const clearCanvas = () => {
    if (!context || !canvasRef.current) return;
    context.clearRect(0, 0, canvasRef.current.width, canvasRef.current.height);
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
        pressureData: enablePressure ? pressurePoints : undefined,
      },
    };

    onSave?.(signature);
  };

  return (
    <div className={className}>
      <canvas
        ref={canvasRef}
        width={width}
        height={height}
        style={{
          border: '1px solid #ccc',
          touchAction: 'none',
          transform: enableOrientation && orientation ? `rotate(${orientation}deg)` : 'none',
        }}
        onTouchStart={startDrawing}
        onTouchMove={draw}
        onTouchEnd={stopDrawing}
      />
      <div style={{ marginTop: '10px' }}>
        <button onClick={clearCanvas}>Clear</button>
        <button onClick={saveSignature} style={{ marginLeft: '10px' }}>
          Save Signature
        </button>
      </div>
      {enablePressure && pressurePoints.length > 0 && (
        <div style={{ fontSize: '12px', color: '#666', marginTop: '5px' }}>
          Pressure points recorded: {pressurePoints.length}
        </div>
      )}
    </div>
  );
};

export default MobileSignatureCanvas;