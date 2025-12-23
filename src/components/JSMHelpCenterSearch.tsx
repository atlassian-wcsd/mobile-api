import React, { useState, useRef, useCallback, useEffect } from 'react';

interface JSMHelpCenterSearchProps {
  onSearch: (query: string) => void;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
}

export const JSMHelpCenterSearch: React.FC<JSMHelpCenterSearchProps> = ({
  onSearch,
  placeholder = "Search help articles...",
  disabled = false,
  className = ''
}) => {
  const [query, setQuery] = useState('');
  const [isComposing, setIsComposing] = useState(false);
  const [isFocused, setIsFocused] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Handle IME composition events for Japanese input
  const handleCompositionStart = useCallback(() => {
    setIsComposing(true);
  }, []);

  const handleCompositionEnd = useCallback((e: React.CompositionEvent<HTMLInputElement>) => {
    setIsComposing(false);
    const value = e.currentTarget.value;
    setQuery(value);
  }, []);

  // Handle input changes with proper IME support
  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    
    // Only update state if not composing (to avoid Japanese input issues)
    if (!isComposing) {
      setQuery(value);
    }
  }, [isComposing]);

  // Handle search submission
  const handleSubmit = useCallback((e: React.FormEvent) => {
    e.preventDefault();
    if (!isComposing && query.trim()) {
      onSearch(query.trim());
    }
  }, [query, isComposing, onSearch]);

  // Handle focus events
  const handleFocus = useCallback(() => {
    setIsFocused(true);
  }, []);

  const handleBlur = useCallback(() => {
    setIsFocused(false);
  }, []);

  // Clear search
  const handleClear = useCallback(() => {
    setQuery('');
    if (inputRef.current) {
      inputRef.current.focus();
    }
  }, []);

  // Handle keyboard events
  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      handleClear();
    }
  }, [handleClear]);

  return (
    <div className={`jsm-help-search-container ${className}`}>
      <form onSubmit={handleSubmit} className="jsm-help-search-form">
        <div className={`jsm-help-search-input-wrapper ${isFocused ? 'focused' : ''}`}>
          <SearchIcon />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={handleInputChange}
            onCompositionStart={handleCompositionStart}
            onCompositionEnd={handleCompositionEnd}
            onFocus={handleFocus}
            onBlur={handleBlur}
            onKeyDown={handleKeyDown}
            placeholder={placeholder}
            disabled={disabled}
            className="jsm-help-search-input"
            autoComplete="off"
            spellCheck="false"
            // Important for Japanese input: prevent autocorrect and autocapitalize
            autoCorrect="off"
            autoCapitalize="off"
          />
          {query && (
            <button
              type="button"
              onClick={handleClear}
              className="jsm-help-search-clear"
              aria-label="Clear search"
            >
              <ClearIcon />
            </button>
          )}
        </div>
      </form>
      
      <style jsx>{`
        .jsm-help-search-container {
          width: 100%;
          max-width: 600px;
          margin: 0 auto;
        }

        .jsm-help-search-form {
          position: relative;
          width: 100%;
        }

        .jsm-help-search-input-wrapper {
          position: relative;
          display: flex;
          align-items: center;
          background: #ffffff;
          border: 2px solid #ddd;
          border-radius: 8px;
          transition: all 0.2s ease;
          box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .jsm-help-search-input-wrapper.focused {
          border-color: #0052cc;
          box-shadow: 0 0 0 3px rgba(0, 82, 204, 0.1);
        }

        .jsm-help-search-input {
          flex: 1;
          padding: 12px 16px 12px 48px;
          border: none;
          outline: none;
          font-size: 16px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Noto Sans', 'Ubuntu', 'Droid Sans', 'Helvetica Neue', sans-serif;
          background: transparent;
          color: #333;
          
          /* Critical fixes for Japanese text overlap issues */
          line-height: 1.5;
          letter-spacing: normal;
          word-spacing: normal;
          text-rendering: optimizeLegibility;
          -webkit-font-smoothing: antialiased;
          -moz-osx-font-smoothing: grayscale;
          
          /* Prevent text overflow and ensure proper spacing */
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          
          /* IME composition styling */
          ime-mode: auto;
          -webkit-ime-mode: auto;
          
          /* Mobile optimizations */
          -webkit-appearance: none;
          -webkit-tap-highlight-color: transparent;
          
          /* Ensure consistent height across different languages */
          min-height: 24px;
          box-sizing: border-box;
        }

        .jsm-help-search-input::placeholder {
          color: #666;
          opacity: 1;
          /* Ensure placeholder doesn't interfere with Japanese input */
          font-style: normal;
          font-weight: normal;
        }

        .jsm-help-search-input:disabled {
          background-color: #f5f5f5;
          color: #999;
          cursor: not-allowed;
        }

        /* Search icon positioning */
        .jsm-help-search-input-wrapper svg:first-child {
          position: absolute;
          left: 16px;
          top: 50%;
          transform: translateY(-50%);
          color: #666;
          pointer-events: none;
          z-index: 1;
        }

        .jsm-help-search-clear {
          position: absolute;
          right: 12px;
          top: 50%;
          transform: translateY(-50%);
          background: none;
          border: none;
          cursor: pointer;
          padding: 4px;
          border-radius: 4px;
          color: #666;
          transition: all 0.2s ease;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .jsm-help-search-clear:hover {
          background-color: #f0f0f0;
          color: #333;
        }

        .jsm-help-search-clear:focus {
          outline: 2px solid #0052cc;
          outline-offset: 2px;
        }

        /* Mobile responsive adjustments */
        @media (max-width: 768px) {
          .jsm-help-search-input {
            font-size: 16px; /* Prevent zoom on iOS */
            padding: 14px 16px 14px 48px;
          }
          
          .jsm-help-search-input-wrapper {
            border-radius: 12px;
          }
        }

        /* High DPI display optimizations */
        @media (-webkit-min-device-pixel-ratio: 2), (min-resolution: 192dpi) {
          .jsm-help-search-input {
            -webkit-font-smoothing: subpixel-antialiased;
          }
        }

        /* Dark mode support */
        @media (prefers-color-scheme: dark) {
          .jsm-help-search-input-wrapper {
            background: #1a1a1a;
            border-color: #444;
          }
          
          .jsm-help-search-input {
            color: #fff;
          }
          
          .jsm-help-search-input::placeholder {
            color: #999;
          }
          
          .jsm-help-search-input-wrapper.focused {
            border-color: #4c9aff;
          }
        }

        /* RTL language support */
        [dir="rtl"] .jsm-help-search-input {
          padding: 12px 48px 12px 16px;
        }
        
        [dir="rtl"] .jsm-help-search-input-wrapper svg:first-child {
          left: auto;
          right: 16px;
        }
        
        [dir="rtl"] .jsm-help-search-clear {
          right: auto;
          left: 12px;
        }
      `}</style>
    </div>
  );
};

const SearchIcon: React.FC = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="11" cy="11" r="8" />
    <path d="m21 21-4.35-4.35" />
  </svg>
);

const ClearIcon: React.FC = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <line x1="18" y1="6" x2="6" y2="18" />
    <line x1="6" y1="6" x2="18" y2="18" />
  </svg>
);