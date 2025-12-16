import { useEffect, useRef } from 'react';
import { feedbackService } from '../services/FeedbackService';

interface MetricsTrackerProps {
  children: React.ReactNode;
}

/**
 * Wrapper component that automatically tracks user metrics
 * Include this at the root of your application
 */
export const MetricsTracker: React.FC<MetricsTrackerProps> = ({ children }) => {
  const pageLoadTime = useRef<number>(Date.now());
  const currentPath = useRef<string>(window.location.pathname);

  useEffect(() => {
    // Track initial page view
    trackPageView();

    // Track page load time
    window.addEventListener('load', handlePageLoad);

    // Track page visibility changes
    document.addEventListener('visibilitychange', handleVisibilityChange);

    // Track errors
    window.addEventListener('error', handleError);
    window.addEventListener('unhandledrejection', handleUnhandledRejection);

    // Clean up
    return () => {
      window.removeEventListener('load', handlePageLoad);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('error', handleError);
      window.removeEventListener('unhandledrejection', handleUnhandledRejection);
    };
  }, []);

  // Track route changes (for single-page applications)
  useEffect(() => {
    const handleRouteChange = () => {
      const newPath = window.location.pathname;
      if (newPath !== currentPath.current) {
        // Track time spent on previous page
        const timeSpent = Date.now() - pageLoadTime.current;
        feedbackService.trackTiming(
          'navigation',
          'page_duration',
          timeSpent,
          { page: currentPath.current }
        );

        // Track new page view
        currentPath.current = newPath;
        pageLoadTime.current = Date.now();
        trackPageView();
      }
    };

    // Listen for history changes (for React Router or similar)
    window.addEventListener('popstate', handleRouteChange);

    // Intercept pushState and replaceState
    const originalPushState = window.history.pushState;
    const originalReplaceState = window.history.replaceState;

    window.history.pushState = function (...args) {
      originalPushState.apply(window.history, args);
      handleRouteChange();
    };

    window.history.replaceState = function (...args) {
      originalReplaceState.apply(window.history, args);
      handleRouteChange();
    };

    return () => {
      window.removeEventListener('popstate', handleRouteChange);
      window.history.pushState = originalPushState;
      window.history.replaceState = originalReplaceState;
    };
  }, []);

  const trackPageView = () => {
    feedbackService.trackPageView(window.location.pathname);
  };

  const handlePageLoad = () => {
    const loadTime = Date.now() - pageLoadTime.current;
    feedbackService.trackTiming('performance', 'page_load', loadTime, {
      page: window.location.pathname,
    });
  };

  const handleVisibilityChange = () => {
    if (document.hidden) {
      feedbackService.trackEvent('engagement', 'page_hidden', {
        page: window.location.pathname,
      });
    } else {
      feedbackService.trackEvent('engagement', 'page_visible', {
        page: window.location.pathname,
      });
    }
  };

  const handleError = (event: ErrorEvent) => {
    feedbackService.trackError(
      new Error(event.message),
      {
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno,
        page: window.location.pathname,
      }
    );
  };

  const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
    feedbackService.trackError(
      event.reason instanceof Error
        ? event.reason
        : new Error(String(event.reason)),
      {
        type: 'unhandledRejection',
        page: window.location.pathname,
      }
    );
  };

  return <>{children}</>;
};

export default MetricsTracker;
