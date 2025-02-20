import React, { useRef, useEffect } from 'react';
import PropTypes from 'prop-types';

const SignatureCanvas = ({ width = 300, height = 150, onSave, backgroundColor = '#fff', penColor = '#000' }) => {
  const canvasRef = useRef(null);
  const isDrawing = useRef(false);
  const lastX = useRef(0);
  const lastY = useRef(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');

    // Set canvas background
    ctx.fillStyle = backgroundColor;
    ctx.fillRect(0, 0, width, height);

    // Set drawing style
    ctx.strokeStyle = penColor;
    ctx.lineWidth = 2;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
  }, [backgroundColor, penColor, width, height]);

  const startDrawing = (e) => {
    const canvas = canvasRef.current;
    const rect = canvas.getBoundingClientRect();
    const x = e.type.includes('touch') 
      ? e.touches[0].clientX - rect.left 
      : e.clientX - rect.left;
    const y = e.type.includes('touch')
      ? e.touches[0].clientY - rect.top
      : e.clientY - rect.top;

    isDrawing.current = true;
    lastX.current = x;
    lastY.current = y;
  };

  const draw = (e) => {
    if (!isDrawing.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    const rect = canvas.getBoundingClientRect();
    const x = e.type.includes('touch')
      ? e.touches[0].clientX - rect.left
      : e.clientX - rect.left;
    const y = e.type.includes('touch')
      ? e.touches[0].clientY - rect.top
      : e.clientY - rect.top;

    ctx.beginPath();
    ctx.moveTo(lastX.current, lastY.current);
    ctx.lineTo(x, y);
    ctx.stroke();

    lastX.current = x;
    lastY.current = y;
  };

  const stopDrawing = () => {
    isDrawing.current = false;
  };

  const clear = () => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = backgroundColor;
    ctx.fillRect(0, 0, width, height);
  };

  const save = () => {
    if (onSave) {
      const dataUrl = canvasRef.current.toDataURL();
      onSave(dataUrl);
    }
  };

  return (
    <div className="signature-canvas-container">
      <canvas
        ref={canvasRef}
        width={width}
        height={height}
        style={{ 
          border: '1px solid #ccc',
          touchAction: 'none'
        }}
        onMouseDown={startDrawing}
        onMouseMove={draw}
        onMouseUp={stopDrawing}
        onMouseOut={stopDrawing}
        onTouchStart={startDrawing}
        onTouchMove={draw}
        onTouchEnd={stopDrawing}
      />
      <div className="signature-canvas-controls">
        <button onClick={clear}>Clear</button>
        <button onClick={save}>Save</button>
      </div>
    </div>
  );
};

SignatureCanvas.propTypes = {
  width: PropTypes.number,
  height: PropTypes.number,
  onSave: PropTypes.func,
  backgroundColor: PropTypes.string,
  penColor: PropTypes.string,
};

export default SignatureCanvas;