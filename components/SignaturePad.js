import React, { useRef } from 'react';
import SignatureCanvas from 'react-signature-canvas';
import styled from 'styled-components';

const SignatureContainer = styled.div`
  width: 100%;
  max-width: 500px;
  margin: 0 auto;
  border: 1px solid #ccc;
  border-radius: 4px;
`;

const SignatureWrapper = styled.div`
  position: relative;
  width: 100%;
  height: 200px;
  background: #fff;
`;

const ButtonContainer = styled.div`
  margin-top: 10px;
  display: flex;
  gap: 10px;
  justify-content: center;
`;

const Button = styled.button`
  padding: 8px 16px;
  border-radius: 4px;
  border: none;
  background-color: #007bff;
  color: white;
  cursor: pointer;
  
  &:hover {
    background-color: #0056b3;
  }
  
  &:disabled {
    background-color: #ccc;
    cursor: not-allowed;
  }
`;

const SignaturePad = ({ onSave }) => {
  const signatureRef = useRef();

  const handleClear = () => {
    signatureRef.current.clear();
  };

  const handleSave = () => {
    if (!signatureRef.current.isEmpty()) {
      const signatureData = signatureRef.current.toDataURL();
      onSave(signatureData);
    }
  };

  return (
    <SignatureContainer>
      <SignatureWrapper>
        <SignatureCanvas
          ref={signatureRef}
          canvasProps={{
            width: 500,
            height: 200,
            className: 'signature-canvas',
            style: {
              width: '100%',
              height: '100%',
              border: 'none',
            }
          }}
          backgroundColor="rgb(255, 255, 255)"
          penColor="black"
          dotSize={2}
          minWidth={2}
          maxWidth={4}
          throttle={16}
          velocityFilterWeight={0.7}
        />
      </SignatureWrapper>
      <ButtonContainer>
        <Button onClick={handleClear}>Clear</Button>
        <Button onClick={handleSave}>Save</Button>
      </ButtonContainer>
    </SignatureContainer>
  );
};

export default SignaturePad;