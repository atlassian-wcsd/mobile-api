import React, { useRef, useEffect, useState } from 'react';
import { Signature } from '../models/Signature';

interface SignatureCanvasProps {
  width?: number;
  height?: number;
  onSave?: (signature: Signature) => void;
  onClear?: () => void;
  className?: string;
  deviceId: string;
  authToken: string;
}

export const SignatureCanvas: React.FC<SignatureCanvasProps> = ({
  width = 500,
  height = 200,
  onSave,
  onClear,
  className,
  deviceId,
  authToken,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [isDrawing, setIsDrawing] = useState(false);
  const [context, setContext] = useState<CanvasRenderingContext2D | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set up canvas
    ctx.lineWidth = 2;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.strokeStyle = '#000000';
    
    setContext(ctx);
  }, []);

  const startDrawing = (e: React.MouseEvent | React.TouchEvent) => {
    setIsDrawing(true);
    const { offsetX, offsetY } = getCoordinates(e);
    context?.beginPath();
    context?.moveTo(offsetX, offsetY);
  };

  const draw = (e: React.MouseEvent | React.TouchEvent) => {
    if (!isDrawing || !context) return;
    e.preventDefault();
    
    const { offsetX, offsetY } = getCoordinates(e);
    context.lineTo(offsetX, offsetY);
    context.stroke();
  };

  const stopDrawing = () => {
    setIsDrawing(false);
    context?.closePath();
  };

  const getCoordinates = (e: React.MouseEvent | React.TouchEvent) => {
    const canvas = canvasRef.current;
    if (!canvas) return { offsetX: 0, offsetY: 0 };

    if ('touches' in e) {
      const touch = e.touches[0];
      const rect = canvas.getBoundingClientRect();
      return {
        offsetX: touch.clientX - rect.left,
        offsetY: touch.clientY - rect.top,
      };
    } else {
      return {
        offsetX: e.nativeEvent.offsetX,
        offsetY: e.nativeEvent.offsetY,
      };
    }
  };

  const clearCanvas = () => {
    if (!context || !canvasRef.current) return;
    context.clearRect(0, 0, canvasRef.current.width, canvasRef.current.height);
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
      deviceInfo: {
        deviceId,
        device: 'browser',
        platform: navigator.userAgent,
        verificationStatus: 'UNVERIFIED', // Will be updated by the service
        authToken,
        pressureData: [], // Could be implemented with pointer events
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
        }}
        onMouseDown={startDrawing}
        onMouseMove={draw}
        onMouseUp={stopDrawing}
        onMouseLeave={stopDrawing}
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
    </div>
  );
};

export default SignatureCanvas;