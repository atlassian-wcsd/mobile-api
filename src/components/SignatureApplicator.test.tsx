import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { SignatureApplicator } from './SignatureApplicator';
import { SignatureService } from '../services/SignatureService';

describe('SignatureApplicator', () => {
  const originalGetContext = HTMLCanvasElement.prototype.getContext;
  const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;

  beforeEach(() => {
    HTMLCanvasElement.prototype.getContext = jest.fn(() => ({
      clearRect: jest.fn(),
      lineTo: jest.fn(),
      stroke: jest.fn(),
      beginPath: jest.fn(),
      moveTo: jest.fn(),
    })) as unknown as typeof HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.toDataURL = jest.fn(() => 'data:image/png;base64,c2lnbmVkLWltYWdl');
  });

  afterEach(() => {
    HTMLCanvasElement.prototype.getContext = originalGetContext;
    HTMLCanvasElement.prototype.toDataURL = originalToDataURL;
    jest.restoreAllMocks();
  });

  it('shows receipt confirmation after successful submission', async () => {
    jest.spyOn(SignatureService.prototype, 'validateSignatureImage').mockReturnValue(true);
    jest.spyOn(SignatureService.prototype, 'createSignature').mockReturnValue({
      id: 'sig-local',
      imageData: 'data:image/png;base64,c2lnbmVkLWltYWdl',
      width: 400,
      height: 200,
      createdAt: new Date(),
      userId: 'user-1',
      metadata: { device: 'web', platform: 'test' },
    });
    jest.spyOn(SignatureService.prototype, 'submitSignature').mockResolvedValue({
      signatureId: 'sig_receipt',
      s3Key: 'signatures/sig_receipt',
      submittedAt: '2026-07-06T12:00:00Z',
      imageHash: 'hash',
    });

    render(
      <SignatureApplicator
        userId="user-1"
        onSignatureApplied={jest.fn()}
        documentWidth={400}
        documentHeight={400}
      />
    );

    fireEvent.click(screen.getByText('Create New Signature'));
    fireEvent.click(screen.getByText('Save Signature'));

    await waitFor(() => {
      expect(screen.getByText(/Signature submitted \(sig_receipt\)/i)).toBeInTheDocument();
    });
  });

  it('shows retry error when submission fails', async () => {
    jest.spyOn(SignatureService.prototype, 'validateSignatureImage').mockReturnValue(true);
    jest.spyOn(SignatureService.prototype, 'createSignature').mockReturnValue({
      id: 'sig-local',
      imageData: 'data:image/png;base64,c2lnbmVkLWltYWdl',
      width: 400,
      height: 200,
      createdAt: new Date(),
      userId: 'user-1',
      metadata: { device: 'web', platform: 'test' },
    });
    jest
      .spyOn(SignatureService.prototype, 'submitSignature')
      .mockRejectedValueOnce(new Error('network failed'));

    render(
      <SignatureApplicator
        userId="user-1"
        onSignatureApplied={jest.fn()}
        documentWidth={400}
        documentHeight={400}
      />
    );

    fireEvent.click(screen.getByText('Create New Signature'));
    fireEvent.click(screen.getByText('Save Signature'));

    await waitFor(() => {
      expect(screen.getByText('Signature submission failed. Please retry.')).toBeInTheDocument();
    });
  });
});
