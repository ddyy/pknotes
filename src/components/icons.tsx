import type { ReactNode, SVGProps } from 'react';

// Hand-drawn 16px stroke glyphs on currentColor — no icon dependency, and
// they pick up each button's muted/danger/accent color for free.
function Icon({ children, ...props }: SVGProps<SVGSVGElement> & { children: ReactNode }) {
  return (
    <svg
      viewBox="0 0 16 16"
      width="15"
      height="15"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...props}
    >
      {children}
    </svg>
  );
}

export const KeyIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <circle cx="4.75" cy="8" r="2.5" />
    <path d="M7.25 8h6.25M11 8v2.25M13.5 8v1.75" />
  </Icon>
);

export const LockIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <rect x="3.25" y="7" width="9.5" height="6.25" rx="1.5" />
    <path d="M5.5 7V5.25a2.5 2.5 0 0 1 5 0V7" />
  </Icon>
);

export const MenuIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M2.75 4.5h10.5M2.75 8h10.5M2.75 11.5h10.5" />
  </Icon>
);

export const EyeIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M1.75 8C3.6 4.9 12.4 4.9 14.25 8 12.4 11.1 3.6 11.1 1.75 8Z" />
    <circle cx="8" cy="8" r="1.75" />
  </Icon>
);

export const PencilIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="m9.7 3.4 2.9 2.9-6.4 6.4-3.6.7.7-3.6ZM8.6 4.5l2.9 2.9" />
  </Icon>
);

export const TrashIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M3 4.5h10M6.5 4.5V3.25h3V4.5M4.5 4.5l.65 7.9a1 1 0 0 0 1 .9h3.7a1 1 0 0 0 1-.9l.65-7.9" />
  </Icon>
);

export const PlusIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M8 3.25v9.5M3.25 8h9.5" />
  </Icon>
);

export const GearIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <circle cx="8" cy="8" r="2.25" />
    <path d="M8 1.9v1.9M8 12.2v1.9M1.9 8h1.9M12.2 8h1.9M3.7 3.7l1.35 1.35M10.95 10.95l1.35 1.35M12.3 3.7l-1.35 1.35M5.05 10.95 3.7 12.3" />
  </Icon>
);

export const DownloadIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M8 2.5v7.75M4.9 7.4 8 10.5l3.1-3.1M3 13.25h10" />
  </Icon>
);

export const RotateIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M13.6 8A5.6 5.6 0 1 1 11.9 4M13.75 1.75V4.5H11" />
  </Icon>
);

export const WarnIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M8 2.4 14.4 13.2H1.6Z" />
    <path d="M8 6.5v3.1" />
    <path d="M8 11.6v.01" />
  </Icon>
);
