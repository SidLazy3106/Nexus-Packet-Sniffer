import { useGSAP } from '@gsap/react'
import gsap from 'gsap'
import { Component, useEffect, useRef } from 'react'
import type { ErrorInfo, ReactNode } from 'react'
import { NpcapBanner, Sidebar, Toasts, TopBar } from './components/Shell'
import { initApp, useApp } from './lib/store'
import type { PageId } from './lib/store'
import Analytics from './pages/Analytics'
import Explorer from './pages/Explorer'
import LiveCapture from './pages/LiveCapture'
import Overview from './pages/Overview'
import Protocols from './pages/Protocols'
import RootCause from './pages/RootCause'
import Sessions from './pages/Sessions'
import SettingsPage from './pages/SettingsPage'

const PAGES: Record<PageId, () => ReactNode> = {
  overview: () => <Overview />,
  capture: () => <LiveCapture />,
  explorer: () => <Explorer />,
  protocols: () => <Protocols />,
  rca: () => <RootCause />,
  analytics: () => <Analytics />,
  sessions: () => <Sessions />,
  settings: () => <SettingsPage />,
}

// Pages that manage their own scrolling (full-height layouts).
const FULL_HEIGHT: ReadonlySet<PageId> = new Set(['capture', 'explorer'])

class Boundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null }
  static getDerivedStateFromError(error: Error) {
    return { error }
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(error, info.componentStack)
  }
  render() {
    if (this.state.error) {
      return (
        <div className="card p-6 max-w-lg mx-auto mt-10 text-sm" role="alert">
          <div className="font-semibold text-crit mb-1">This view hit an unexpected error</div>
          <p className="text-dim text-xs leading-5 break-words">{this.state.error.message}</p>
          <button className="btn mt-4" onClick={() => this.setState({ error: null })}>Try again</button>
        </div>
      )
    }
    return this.props.children
  }
}

export default function App() {
  const page = useApp((s) => s.page)
  const theme = useApp((s) => s.settings?.theme ?? 'dark')

  const stage = useRef<HTMLDivElement>(null)
  // Pages settle in quietly; skipped entirely when the user prefers reduced motion.
  useGSAP(
    () => {
      const mm = gsap.matchMedia()
      mm.add('(prefers-reduced-motion: no-preference)', () => {
        gsap.from(stage.current, { opacity: 0, y: 8, duration: 0.35, ease: 'power1.out', clearProps: 'all' })
      })
      return () => mm.revert()
    },
    { dependencies: [page], scope: stage },
  )

  useEffect(() => {
    document.documentElement.dataset.theme = theme
  }, [theme])

  useEffect(() => {
    let off: (() => void) | undefined
    let cancelled = false
    initApp().then((fn) => {
      if (cancelled) fn()
      else off = fn
    })
    return () => {
      cancelled = true
      off?.()
    }
  }, [])

  return (
    <div className="h-full flex flex-col">
      <TopBar />
      <div className="flex flex-1 min-h-0">
        <Sidebar />
        <main className="flex-1 min-w-0 min-h-0 flex flex-col">
          <NpcapBanner />
          <div className={`flex-1 min-h-0 p-4 ${FULL_HEIGHT.has(page) ? 'overflow-hidden' : 'overflow-y-auto'}`}>
            <div ref={stage} className={FULL_HEIGHT.has(page) ? 'h-full' : ''}>
              <Boundary key={page}>{PAGES[page]()}</Boundary>
            </div>
          </div>
        </main>
      </div>
      <Toasts />
    </div>
  )
}
