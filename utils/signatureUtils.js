/**
 * Utility functions for optimizing handwriting display and managing canvas settings
 */

/**
 * Initializes canvas context with optimal settings for clear handwriting
 * @param {CanvasRenderingContext2D} ctx - The canvas 2D rendering context
 * @param {Object} options - Configuration options
 * @param {string} options.strokeColor - Color of the signature stroke
 * @param {number} options.strokeWidth - Width of the signature stroke
 */
export const initializeCanvasContext = (ctx, { strokeColor = '#000000', strokeWidth = 2 }) => {
  // Set basic stroke properties
  ctx.strokeStyle = strokeColor;
  ctx.lineWidth = strokeWidth;
  
  // Set line endings to round for smoother appearance
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';
  
  // Enable anti-aliasing for smoother lines
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = 'high';
};

/**
 * Calculates the drawing coordinates relative to canvas position
 * @param {MouseEvent|TouchEvent} event - The input event
 * @param {DOMRect} canvasRect - The canvas bounding rectangle
 * @returns {Object} The calculated X and Y coordinates
 */
export const getDrawingCoordinates = (event, canvasRect) => {
  const clientX = event.touches ? event.touches[0].clientX : event.clientX;
  const clientY = event.touches ? event.touches[0].clientY : event.clientY;
  
  return {
    x: clientX - canvasRect.left,
    y: clientY - canvasRect.top
  };
};

/**
 * Draws a smooth line segment between two points
 * @param {CanvasRenderingContext2D} ctx - The canvas 2D rendering context
 * @param {number} startX - Starting X coordinate
 * @param {number} startY - Starting Y coordinate
 * @param {number} endX - Ending X coordinate
 * @param {number} endY - Ending Y coordinate
 */
export const drawSmoothLine = (ctx, startX, startY, endX, endY) => {
  ctx.beginPath();
  ctx.moveTo(startX, startY);
  ctx.lineTo(endX, endY);
  ctx.stroke();
};

/**
 * Clears the canvas content
 * @param {CanvasRenderingContext2D} ctx - The canvas 2D rendering context
 * @param {number} width - Canvas width
 * @param {number} height - Canvas height
 */
export const clearCanvas = (ctx, width, height) => {
  ctx.clearRect(0, 0, width, height);
};

/**
 * Sets the canvas resolution for better display quality
 * @param {HTMLCanvasElement} canvas - The canvas element
 * @param {number} width - Desired width
 * @param {number} height - Desired height
 */
export const setCanvasResolution = (canvas, width, height) => {
  // Get the display pixel ratio for high DPI screens
  const pixelRatio = window.devicePixelRatio || 1;
  
  // Set the canvas size in pixels
  canvas.width = width * pixelRatio;
  canvas.height = height * pixelRatio;
  
  // Scale the canvas back to desired size
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  
  // Scale the context to account for pixel ratio
  const ctx = canvas.getContext('2d');
  ctx.scale(pixelRatio, pixelRatio);
  
  return ctx;
};

/**
 * Optimizes touch input for smoother drawing
 * @param {HTMLCanvasElement} canvas - The canvas element
 */
export const optimizeTouchInput = (canvas) => {
  canvas.style.touchAction = 'none';
  canvas.style.msTouchAction = 'none';
  canvas.style.userSelect = 'none';
  canvas.style.webkitUserSelect = 'none';
  canvas.style.webkitTapHighlightColor = 'rgba(0,0,0,0)';
};

/**
 * Saves the signature as a data URL
 * @param {HTMLCanvasElement} canvas - The canvas element
 * @param {string} format - Image format (default: 'image/png')
 * @param {number} quality - Image quality for JPEG format (0-1)
 * @returns {string} The signature as a data URL
 */
export const saveSignature = (canvas, format = 'image/png', quality = 1.0) => {
  return canvas.toDataURL(format, quality);
};