import React, { useState, useRef, useCallback, useEffect } from 'react';
import './JSMHelpCenterSearch.css';

interface JSMHelpCenterSearchProps {
  onSearch: (query: string) => void;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  autoFocus?: boolean;
  maxLength?: number;
  debounceMs?: number;
  onClear?: () => void;
  onFocus?: () => void;
  onBlur?: () => void;
}

export const JSMHelpCenterSearch: React.FC<JSMHelpCenterSearchProps> = ({
  onSearch,
  placeholder = "Search help articles...",
  disabled = false,
  className = '',
  autoFocus = false,
  maxLength = 200,
  debounceMs = 300,
  onClear,
  onFocus,
  onBlur
}) => {
  const [query, setQuery] = useState('');
  const [isComposing, setIsComposing] = useState(false);
  const [isFocused, setIsFocused] = useState(false);
  const [compositionValue, setCompositionValue] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const debounceTimeoutRef = useRef<NodeJS.Timeout>();

  // Auto-focus on mount if requested
  useEffect(() => {
    if (autoFocus && inputRef.current) {
      inputRef.current.focus();
    }
  }, [autoFocus]);

  // Debounced search
  useEffect(() => {
    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }

    if (query.trim() && !isComposing) {
      debounceTimeoutRef.current = setTimeout(() => {
        onSearch(query.trim());
      }, debounceMs);
    }

    return () => {
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
    };
  }, [query, isComposing, onSearch, debounceMs]);

  // Handle IME composition start (Japanese, Chinese, Korean input)
  const handleCompositionStart = useCallback((e: React.CompositionEvent<HTMLInputElement>) => {
    setIsComposing(true);
    setCompositionValue(e.currentTarget.value);
  }, []);

  // Handle IME composition update
  const handleCompositionUpdate = useCallback((e: React.CompositionEvent<HTMLInputElement>) => {
    // Store the composition value to prevent premature updates
    setCompositionValue(e.currentTarget.value);
  }, []);

  // Handle IME composition end
  const handleCompositionEnd = useCallback((e: React.CompositionEvent<HTMLInputElement>) => {
    setIsComposing(false);
    const value = e.currentTarget.value;
    setQuery(value);
    setCompositionValue('');
  }, []);

  // Handle input changes with proper IME support
  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    
    // Respect maxLength
    if (maxLength && value.length > maxLength) {
      return;
    }
    
    // Only update state if not composing (to avoid Japanese input issues)
    if (!isComposing) {
      setQuery(value);
    } else {
      // During composition, store the intermediate value
      setCompositionValue(value);
    }
  }, [isComposing, maxLength]);

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
    onFocus?.();
  }, [onFocus]);

  const handleBlur = useCallback(() => {
    setIsFocused(false);
    onBlur?.();
  }, [onBlur]);

  // Clear search
  const handleClear = useCallback(() => {
    setQuery('');
    setCompositionValue('');
    if (inputRef.current) {
      inputRef.current.focus();
    }
    onClear?.();
  }, [onClear]);

  // Handle keyboard events
  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      handleClear();
    } else if (e.key === 'Enter' && !isComposing) {
      // Prevent form submission during IME composition
      handleSubmit(e);
    }
  }, [handleClear, handleSubmit, isComposing]);

  // Get the display value (composition value during IME input, otherwise query)
  const displayValue = isComposing ? compositionValue : query;

  return (
    <div className={`jsm-help-search-container ${className}`}>
      <form onSubmit={handleSubmit} className="jsm-help-search-form" role="search">
        <div 
          className={`jsm-help-search-input-wrapper ${isFocused ? 'focused' : ''} ${isComposing ? 'composing' : ''}`}
          data-testid="search-wrapper"
        >
          <SearchIcon className="jsm-help-search-icon" />
          <input
            ref={inputRef}
            type="text"
            value={displayValue}
            onChange={handleInputChange}
            onCompositionStart={handleCompositionStart}
            onCompositionUpdate={handleCompositionUpdate}
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
            // Accessibility attributes
            aria-label="Search help articles"
            aria-describedby="search-help-text"
            role="searchbox"
            // Additional attributes for better mobile experience
            inputMode="search"
            maxLength={maxLength}
            data-testid="search-input"
          />
          {(query || compositionValue) && (
            <button
              type="button"
              onClick={handleClear}
              className="jsm-help-search-clear"
              aria-label="Clear search"
              tabIndex={0}
              data-testid="clear-button"
            >
              <ClearIcon className="jsm-help-search-clear-icon" />
            </button>
          )}
        </div>
        <div id="search-help-text" className="sr-only">
          Use this search box to find help articles. Japanese input is supported.
        </div>
      </form>
    </div>
  );
};

// Search icon component
const SearchIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg 
    className={className}
    width="20" 
    height="20" 
    viewBox="0 0 24 24" 
    fill="none" 
    stroke="currentColor" 
    strokeWidth="2"
    aria-hidden="true"
  >
    <circle cx="11" cy="11" r="8" />
    <path d="m21 21-4.35-4.35" />
  </svg>
);

// Clear icon component
const ClearIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg 
    className={className}
    width="16" 
    height="16" 
    viewBox="0 0 24 24" 
    fill="none" 
    stroke="currentColor" 
    strokeWidth="2"
    aria-hidden="true"
  >
    <line x1="18" y1="6" x2="6" y2="18" />
    <line x1="6" y1="6" x2="18" y2="18" />
  </svg>
);

export default JSMHelpCenterSearch;