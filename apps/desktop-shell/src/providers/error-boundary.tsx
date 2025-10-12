import { Component, type ReactNode } from 'react';
import { toast } from 'sonner';

import { CrashDiagnostics } from '../components/crash-diagnostics';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export class AppErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error) {
    console.error('Unhandled error boundary exception', error);
    toast.error(error.message ?? 'An unexpected error occurred');
  }

  render() {
    if (this.state.hasError) {
      return <CrashDiagnostics errorMessage={this.state.error?.message} />;
    }

    return this.props.children;
  }
}
