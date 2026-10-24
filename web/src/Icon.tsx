// Material Symbols–style outline icons, drawn on a 24px grid.
const PATHS: Record<string, string> = {
  lines: 'M5 7h14M5 12h9M5 17h11',
  file: 'M7 3h7l5 5v13H7zM14 3v5h5',
  play: 'M8 5v14l11-7z',
  pause: 'M8 5v14M16 5v14',
  filter: 'M4 6h16M7 12h10M10 18h4',
  close: 'M6 6l12 12M18 6L6 18',
  warning: 'M12 4l9 16H3zM12 10v4M12 17v.5',
  moon: 'M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z',
  sun: 'M12 8a4 4 0 1 1 0 8a4 4 0 0 1 0-8zM12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
  auto: 'M12 3a9 9 0 1 1 0 18a9 9 0 0 1 0-18zM12 3v18',
  radar: 'M12 12m-8 0a8 8 0 1 0 16 0a8 8 0 1 0-16 0M12 12m-4 0a4 4 0 1 0 8 0a4 4 0 1 0-8 0M12 12l6-6',
  inbox: 'M4 13l3-8h10l3 8v6H4zM4 13h5l1 2h4l1-2h5',
  up: 'M12 19V5M6 11l6-6 6 6',
  down: 'M12 5v14M6 13l6 6 6-6',
  copy: 'M9 9h10v11H9zM5 15V4h10',
  info: 'M12 3a9 9 0 1 1 0 18a9 9 0 0 1 0-18zM12 11v6M12 7.5v.5',
  error: 'M12 3a9 9 0 1 1 0 18a9 9 0 0 1 0-18zM9 9l6 6M15 9l-6 6',
};

export function Icon({ name, size = 16 }: { name: string; size?: number }) {
  return (
    <svg class="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path d={PATHS[name] ?? ''} fill={name === 'play' ? 'currentColor' : 'none'} />
    </svg>
  );
}
