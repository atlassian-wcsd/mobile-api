import React, { useState, useEffect, useRef } from 'react';
import { Signature } from '../models/Signature';
import { SignatureService } from '../services/SignatureService';

interface SignatureApplicatorProps {
  userId: string;
  onSignatureApplied: (signature: Signature, position: { x: number; y: number }) => void;
  documentWidth: number;
  documentHeight: number;
}

export const SignatureApplicator: React.FC<SignatureApplicatorProps> = ({
  userId,
  onSignatureApplied,
  documentWidth,
  documentHeight,
}) => {
  const [signatures, setSignatures] = useState<Signature[]>([]);
  const [selectedSignature, setSelectedSignature] = useState<Signature | null>(null);
  const [isDrawing, setIsDrawing] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const signatureService = new SignatureService();

  // Load user's signatures
  useEffect(() => {
    const userSignatures = signatureService.getUserSignatures(userId);
    setSignatures(userSignatures);
  }, [userId]);

  // Handle new signature creation
  const handleCreateSignature = async (event: React.MouseEvent<HTMLButtonElement>) => {
    if (!canvasRef.current) return;

    const canvas = canvasRef.current;
    const context = canvas.getContext('2d');
    if (!context) return;

    // Clear previous drawings
    context.clearRect(0, 0, canvas.width, canvas.height);
    setIsDrawing(true);
  };

  // Handle drawing on canvas
  const handleDraw = (event: React.MouseEvent<HTMLCanvasElement>) => {
    if (!isDrawing || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const context = canvas.getContext('2d');
    if (!context) return;

    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    context.lineWidth = 2;
    context.lineCap = 'round';
    context.lineTo(x, y);
    context.stroke();
    context.beginPath();
    context.moveTo(x, y);
  };

  // Handle saving the signature
  const handleSaveSignature = () => {
    if (!canvasRef.current) return;

    const canvas = canvasRef.current;
    const imageData = canvas.toDataURL('image/png');
    
    if (signatureService.validateSignatureImage(imageData)) {
      const newSignature = signatureService.createSignature(
        imageData,
        canvas.width,
        canvas.height,
        userId,
        {
          device: 'web',
          platform: navigator.userAgent,
        }
      );

      setSignatures([...signatures, newSignature]);
      setIsDrawing(false);
      
      // Clear canvas
      const context = canvas.getContext('2d');
      if (context) {
        context.clearRect(0, 0, canvas.width, canvas.height);
      }
    }
  };

  // Handle applying signature to document
  const handleApplySignature = (event: React.MouseEvent<HTMLDivElement>) => {
    if (!selectedSignature) return;

    const rect = event.currentTarget.getBoundingClientRect();
    const position = {
      x: event.clientX - rect.left,
      y: event.clientY - rect.top,
    };

    onSignatureApplied(selectedSignature, position);
  };

  return (
    <div className="signature-applicator">
      <div className="signature-tools">
        <button onClick={handleCreateSignature}>
          Create New Signature
        </button>
        
        <div className="signature-list">
          {signatures.map((signature) => (
            <div
              key={signature.id}
              className={`signature-item ${selectedSignature?.id === signature.id ? 'selected' : ''}`}
              onClick={() => setSelectedSignature(signature)}
            >
              <img
                src={signature.imageData}
                alt={signature.label || 'Signature'}
                style={{ width: '100px', height: 'auto' }}
              />
              <span>{signature.label || 'Untitled Signature'}</span>
            </div>
          ))}
        </div>
      </div>

      {isDrawing && (
        <div className="signature-canvas-container">
          <canvas
            ref={canvasRef}
            width={400}
            height={200}
            onMouseMove={handleDraw}
            onMouseDown={() => setIsDrawing(true)}
            onMouseUp={() => setIsDrawing(false)}
            onMouseLeave={() => setIsDrawing(false)}
            style={{ border: '1px solid #ccc' }}
          />
          <div className="canvas-controls">
            <button onClick={handleSaveSignature}>Save Signature</button>
            <button onClick={() => setIsDrawing(false)}>Cancel</button>
          </div>
        </div>
      )}

      {selectedSignature && (
        <div
          className="document-preview"
          style={{
            width: documentWidth,
            height: documentHeight,
            position: 'relative',
            border: '1px solid #ccc'
          }}
          onClick={handleApplySignature}
        >
          <div className="document-instructions">
            Click anywhere to place the selected signature
          </div>
        </div>
      )}

      <style jsx>{`
        .signature-applicator {
          display: flex;
          flex-direction: column;
          gap: 20px;
          padding: 20px;
        }

        .signature-tools {
          display: flex;
          flex-direction: column;
          gap: 10px;
        }

        .signature-list {
          display: flex;
          gap: 10px;
          flex-wrap: wrap;
        }

        .signature-item {
          border: 1px solid #ddd;
          padding: 10px;
          cursor: pointer;
          transition: border-color 0.2s;
        }

        .signature-item.selected {
          border-color: #007bff;
        }

        .signature-canvas-container {
          display: flex;
          flex-direction: column;
          gap: 10px;
          align-items: center;
        }

        .canvas-controls {
          display: flex;
          gap: 10px;
        }

        .document-instructions {
          position: absolute;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          color: #666;
          pointer-events: none;
        }

        button {
          padding: 8px 16px;
          background-color: #007bff;
          color: white;
          border: none;
          border-radius: 4px;
          cursor: pointer;
        }

        button:hover {
          background-color: #0056b3;
        }
      `}</style>
    </div>
  );
};