export default function Footer() {
    return (
        <footer className="bg-[var(--color-emerald-900)] text-white pt-16 pb-10 relative overflow-hidden">
            {/* Abstract Background Shape */}
            <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-[var(--color-emerald-800)]/30 rounded-full blur-3xl -translate-y-1/2 translate-x-1/4" />

            <div className="max-w-[960px] mx-auto px-6 relative z-10">
                <div className="text-center">
                    {/* Thank you icon */}
                    <div className="mb-6 inline-flex items-center justify-center p-3 rounded-full bg-[var(--color-emerald-800)]/50 text-[var(--color-primary)]">
                        <span className="material-symbols-outlined text-2xl">favorite</span>
                    </div>

                    <h3
                        className="text-3xl text-white mb-3"
                        style={{ fontFamily: 'var(--font-serif)' }}
                    >
                        Thank You for Visiting
                    </h3>

                    <p className="text-slate-400 mb-4 font-light max-w-md mx-auto">
                        Thank you for exploring my research and write-ups. Knowledge grows when shared — keep learning.
                    </p>

                    <div className="mt-10 text-[var(--color-emerald-800)] text-sm">
                        © {new Date().getFullYear()} Library. All rights reserved.
                    </div>
                </div>
            </div>
        </footer>
    );
}
