import React, { useState } from 'react';
import { JSMHelpCenterSearch } from './JSMHelpCenterSearch.improved';

export const JSMHelpCenterDemo: React.FC = () => {
  const [searchResults, setSearchResults] = useState<string[]>([]);
  const [lastQuery, setLastQuery] = useState<string>('');

  const handleSearch = (query: string) => {
    setLastQuery(query);
    
    // Mock search results for demonstration
    const mockResults = [
      `Help article about "${query}"`,
      `FAQ: How to use ${query}`,
      `Troubleshooting ${query} issues`,
      `Best practices for ${query}`,
      `${query} configuration guide`
    ];
    
    setSearchResults(mockResults);
  };

  const handleClear = () => {
    setSearchResults([]);
    setLastQuery('');
  };

  return (
    <div style={{ padding: '20px', maxWidth: '800px', margin: '0 auto' }}>
      <h1>JSM Help Center Search - Japanese Input Fix Demo</h1>
      <p>
        This demo showcases the fix for Japanese text overlap issues (MOBL-2172).
        Try typing in Japanese, Chinese, or Korean to test IME composition handling.
      </p>
      
      <div style={{ marginBottom: '20px' }}>
        <h2>Test Cases:</h2>
        <ul>
          <li><strong>Japanese:</strong> こんにちは、ヘルプが必要です</li>
          <li><strong>Chinese:</strong> 你好，我需要帮助</li>
          <li><strong>Korean:</strong> 안녕하세요, 도움이 필요합니다</li>
          <li><strong>Mixed:</strong> Hello こんにちは 你好</li>
        </ul>
      </div>

      <div style={{ marginBottom: '30px' }}>
        <JSMHelpCenterSearch
          onSearch={handleSearch}
          onClear={handleClear}
          placeholder="Search help articles... (Japanese input supported)"
          debounceMs={500}
        />
      </div>

      {lastQuery && (
        <div style={{ marginBottom: '20px' }}>
          <h3>Search Query: "{lastQuery}"</h3>
          <p style={{ color: '#666', fontSize: '14px' }}>
            Character count: {lastQuery.length} | 
            Byte length: {new Blob([lastQuery]).size} bytes
          </p>
        </div>
      )}

      {searchResults.length > 0 && (
        <div>
          <h3>Search Results:</h3>
          <ul style={{ listStyle: 'none', padding: 0 }}>
            {searchResults.map((result, index) => (
              <li 
                key={index}
                style={{
                  padding: '12px',
                  margin: '8px 0',
                  backgroundColor: '#f5f5f5',
                  borderRadius: '6px',
                  border: '1px solid #ddd'
                }}
              >
                {result}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div style={{ marginTop: '40px', padding: '20px', backgroundColor: '#f0f8ff', borderRadius: '8px' }}>
        <h3>🔧 Fixes Applied for MOBL-2172:</h3>
        <ul>
          <li>✅ Proper IME composition event handling</li>
          <li>✅ Optimized line-height for CJK characters (1.6-1.8)</li>
          <li>✅ Japanese-specific font stack with fallbacks</li>
          <li>✅ Prevented text overflow and character overlap</li>
          <li>✅ Mobile-responsive design with proper touch targets</li>
          <li>✅ Z-index management for IME composition windows</li>
          <li>✅ Font feature settings for better CJK rendering</li>
          <li>✅ Proper character spacing and baseline alignment</li>
        </ul>
      </div>

      <div style={{ marginTop: '20px', padding: '20px', backgroundColor: '#fff3cd', borderRadius: '8px' }}>
        <h3>🧪 Testing Instructions:</h3>
        <ol>
          <li>Switch your input method to Japanese (Hiragana)</li>
          <li>Type "konnichiwa" and observe the composition</li>
          <li>Confirm the input and verify no text overlap occurs</li>
          <li>Try typing long Japanese phrases to test line-height</li>
          <li>Test on mobile devices for responsive behavior</li>
        </ol>
      </div>
    </div>
  );
};

export default JSMHelpCenterDemo;