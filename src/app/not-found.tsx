import Link from 'next/link';

export default function NotFound() {
    return (
        <div className="min-h-screen flex items-center justify-center pt-16 pb-20 animate-fadeIn relative overflow-hidden bg-[var(--color-bg-light)] dark:bg-[var(--color-bg-dark)]">
            {/* Decorative Background Elements */}
            <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-[var(--color-primary)]/10 rounded-full blur-[100px] pointer-events-none" />
            <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-[var(--color-gold)]/5 rounded-full blur-[100px] pointer-events-none" />

            <div className="max-w-3xl mx-auto px-6 text-center relative z-10">
                <div className="mb-8 relative inline-block">
                    <span
                        className="text-[150px] md:text-[200px] font-bold leading-none text-transparent bg-clip-text bg-gradient-to-r from-[var(--color-emerald-800)] to-[var(--color-emerald-600)] dark:from-[var(--color-primary)] dark:to-[var(--color-emerald-400)] opacity-20"
                        style={{ fontFamily: 'var(--font-serif)' }}
                    >
                        404
                    </span>
                    <div className="absolute inset-0 flex items-center justify-center">
                        <span className="material-symbols-outlined text-6xl md:text-8xl text-[var(--color-emerald-900)] dark:text-[var(--color-primary)] drop-shadow-lg">
                            find_in_page
                        </span>
                    </div>
                </div>

                <h1
                    className="text-4xl md:text-5xl font-bold text-[var(--color-emerald-950)] dark:text-white mb-6 tracking-tight"
                    style={{ fontFamily: 'var(--font-serif)' }}
                >
                    Page Not Found
                </h1>

                <p className="text-lg text-slate-600 dark:text-slate-400 mb-10 max-w-xl mx-auto leading-relaxed">
                    The manuscript you're searching for seems to have been misplaced in the archives. It might have been moved, renamed, or perhaps it never existed.
                </p>

                <Link
                    href="/"
                    className="inline-flex items-center gap-2 px-8 py-4 bg-[var(--color-emerald-900)] hover:bg-[var(--color-emerald-800)] text-[var(--color-sand)] dark:bg-[var(--color-primary)] dark:hover:bg-[var(--color-primary)]/80 dark:text-[var(--color-emerald-950)] rounded-full font-medium transition-all duration-300 shadow-lg"
                >
                    <span className="material-symbols-outlined text-xl">arrow_back</span>
                    Return to Library
                </Link>
            </div>
        </div>
    );
}
