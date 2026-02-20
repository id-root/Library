import Link from 'next/link';

export default function Home() {
  return (
    <div className="animate-fadeIn">
      {/* Hero Section */}
      <section className="relative min-h-screen flex flex-col items-center justify-center px-6 overflow-hidden">
        {/* Subtle decorative elements */}
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-[var(--color-primary)]/5 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-[var(--color-emerald-800)]/5 dark:bg-[var(--color-primary)]/3 rounded-full blur-3xl" />

        <div className="relative z-10 text-center max-w-3xl mx-auto">
          {/* Subtitle */}
          <p className="text-xs sm:text-sm font-semibold tracking-[0.3em] uppercase mb-8 text-[var(--color-gold)]">
            A Curated Digital Archive
          </p>

          {/* Main Title */}
          <h1 className="mb-8">
            <span
              className="block text-5xl sm:text-6xl md:text-7xl lg:text-8xl font-bold text-[var(--color-emerald-950)] dark:text-white leading-[1.05] tracking-tight"
              style={{ fontFamily: 'var(--font-serif)' }}
            >
              The Knowledge
            </span>
            <span
              className="block text-5xl sm:text-6xl md:text-7xl lg:text-8xl font-bold italic text-[var(--color-emerald-950)] dark:text-[var(--color-primary)] leading-[1.05]"
              style={{ fontFamily: 'var(--font-serif)' }}
            >
              Vault
            </span>
          </h1>

          {/* Description */}
          <p className="text-base sm:text-lg text-slate-600 dark:text-slate-400 max-w-xl mx-auto mb-12 leading-relaxed font-light">
            A refined collection of research papers and deep-dive write-ups
            designed for the intellectual explorer. Exploration without friction.
          </p>

          {/* CTA Button */}
          <Link
            href="/publications"
            className="inline-flex items-center gap-2 text-sm font-semibold tracking-wider uppercase border-b-2 border-[var(--color-emerald-950)] dark:border-[var(--color-primary)] text-[var(--color-emerald-950)] dark:text-[var(--color-primary)] pb-1 hover:gap-3 transition-all duration-300"
          >
            Begin Exploration
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 5v14M5 12l7 7 7-7" />
            </svg>
          </Link>
        </div>

        {/* Scroll indicator */}
        <div className="absolute bottom-12 left-1/2 -translate-x-1/2 animate-bounce opacity-30">
          <svg className="w-6 h-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
            <path d="M19 14l-7 7m0 0l-7-7m7 7V3" />
          </svg>
        </div>
      </section>

      {/* Featured Section */}
      <section className="max-w-5xl mx-auto px-6 pb-24">
        <div className="grid md:grid-cols-3 gap-8">
          {[
            {
              icon: 'security',
              title: 'Security Research',
              desc: 'Deep-dive analyses of CTF challenges, vulnerability exploitation, and penetration testing methodologies.',
            },
            {
              icon: 'terminal',
              title: 'Technical Write-ups',
              desc: 'Step-by-step walkthroughs of complex challenges including binary exploitation and network attacks.',
            },
            {
              icon: 'school',
              title: 'Knowledge Sharing',
              desc: 'Documenting the journey of learning through hands-on exploration and problem-solving.',
            },
          ].map((item) => (
            <div
              key={item.title}
              className="p-8 rounded-2xl border border-[var(--color-primary)]/20 dark:border-[var(--color-primary)]/10 bg-white/50 dark:bg-white/[0.02] backdrop-blur-sm hover:border-[var(--color-primary)]/50 transition-all duration-300 group"
            >
              <span className="material-symbols-outlined text-3xl text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] mb-4 block group-hover:scale-110 transition-transform">
                {item.icon}
              </span>
              <h3
                className="text-lg font-bold mb-2 text-[var(--color-emerald-900)] dark:text-white"
                style={{ fontFamily: 'var(--font-serif)' }}
              >
                {item.title}
              </h3>
              <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
                {item.desc}
              </p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
