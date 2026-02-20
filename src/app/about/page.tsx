export default function AboutPage() {
    return (
        <div className="pt-24 pb-20 animate-fadeIn">
            <div className="max-w-3xl mx-auto px-6">
                {/* Header */}
                <div className="mb-16 text-center">
                    <p className="text-xs font-semibold tracking-[0.3em] uppercase mb-4 text-[var(--color-gold)]">
                        Behind the Archive
                    </p>
                    <h1
                        className="text-4xl md:text-5xl font-bold text-[var(--color-emerald-950)] dark:text-white mb-6"
                        style={{ fontFamily: 'var(--font-serif)' }}
                    >
                        About
                    </h1>
                    <div className="w-16 h-0.5 bg-[var(--color-primary)] mx-auto" />
                </div>

                {/* Content */}
                <div className="prose-article">
                    {/* Avatar & Intro */}
                    <div className="flex flex-col items-center mb-12">
                        <div className="w-24 h-24 rounded-full bg-gradient-to-br from-[var(--color-emerald-800)] to-[var(--color-emerald-900)] flex items-center justify-center mb-6 ring-4 ring-[var(--color-primary)]/20">
                            <span className="material-symbols-outlined text-4xl text-[var(--color-primary)]">
                                person
                            </span>
                        </div>
                        <p className="text-center text-lg text-slate-600 dark:text-slate-400 max-w-lg leading-relaxed font-light">
                            Hii I am Vector. Waiting for AGI... Exploring cybersecurity, automation, and open‑source learning not to arrive but to continue...
                        </p>
                    </div>

                    {/* Skills Section */}
                    <div className="grid md:grid-cols-2 gap-8 mb-16">
                        <div className="p-6 rounded-2xl border border-[var(--color-primary)]/20 dark:border-[var(--color-primary)]/10 bg-white/50 dark:bg-white/[0.02]">
                            <span className="material-symbols-outlined text-2xl text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] mb-3 block">
                                shield
                            </span>
                            <h3
                                className="text-lg font-bold mb-2 text-[var(--color-emerald-900)] dark:text-white"
                                style={{ fontFamily: 'var(--font-serif)' }}
                            >
                                Offensive Security
                            </h3>
                            <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
                                Penetration testing, red teaming, vulnerability assessment, and exploit development.
                                Experienced in CTF competitions and real-world security assessments.
                            </p>
                        </div>

                        <div className="p-6 rounded-2xl border border-[var(--color-primary)]/20 dark:border-[var(--color-primary)]/10 bg-white/50 dark:bg-white/[0.02]">
                            <span className="material-symbols-outlined text-2xl text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] mb-3 block">
                                memory
                            </span>
                            <h3
                                className="text-lg font-bold mb-2 text-[var(--color-emerald-900)] dark:text-white"
                                style={{ fontFamily: 'var(--font-serif)' }}
                            >
                                Binary Exploitation
                            </h3>
                            <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
                                Reverse engineering, heap exploitation, ROP chains, FSOP, and modern mitigation bypass
                                techniques. Deep knowledge of ELF internals and glibc.
                            </p>
                        </div>

                        <div className="p-6 rounded-2xl border border-[var(--color-primary)]/20 dark:border-[var(--color-primary)]/10 bg-white/50 dark:bg-white/[0.02]">
                            <span className="material-symbols-outlined text-2xl text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] mb-3 block">
                                lan
                            </span>
                            <h3
                                className="text-lg font-bold mb-2 text-[var(--color-emerald-900)] dark:text-white"
                                style={{ fontFamily: 'var(--font-serif)' }}
                            >
                                Network Security
                            </h3>
                            <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
                                Network pivoting, Active Directory attacks, SSRF exploitation, DNS poisoning,
                                and multi-stage network penetration across complex environments.
                            </p>
                        </div>

                        <div className="p-6 rounded-2xl border border-[var(--color-primary)]/20 dark:border-[var(--color-primary)]/10 bg-white/50 dark:bg-white/[0.02]">
                            <span className="material-symbols-outlined text-2xl text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] mb-3 block">
                                code
                            </span>
                            <h3
                                className="text-lg font-bold mb-2 text-[var(--color-emerald-900)] dark:text-white"
                                style={{ fontFamily: 'var(--font-serif)' }}
                            >
                                Development
                            </h3>
                            <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
                                Python, Rust, C/C++, Assembly. Building custom exploit tools, reverse engineering
                                frameworks, and security automation scripts.
                            </p>
                        </div>
                    </div>

                    {/* Philosophy */}
                    <div className="text-center mb-12">
                        <blockquote className="text-xl italic text-[var(--color-emerald-900)] dark:text-[var(--color-primary)] max-w-lg mx-auto leading-relaxed" style={{ fontFamily: 'var(--font-serif)' }}>
                            &ldquo;The best way to understand a system's security is to think like the adversary.
                            Every vulnerability tells a story — my white-papers are those stories, documented.&rdquo;
                        </blockquote>
                    </div>

                    {/* Stats */}
                    <div className="grid grid-cols-3 gap-4 mb-12">
                        {[
                            { value: '4+', label: 'Write-ups Published' },
                            { value: '15+', label: 'Flags Captured' },
                            { value: 'CTF', label: 'Competitions' },
                        ].map((stat) => (
                            <div key={stat.label} className="text-center p-6 rounded-xl bg-[var(--color-primary)]/5 dark:bg-[var(--color-primary)]/5">
                                <div
                                    className="text-3xl font-bold text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] mb-1"
                                    style={{ fontFamily: 'var(--font-serif)' }}
                                >
                                    {stat.value}
                                </div>
                                <div className="text-xs text-slate-500 dark:text-slate-400 font-medium uppercase tracking-wider">
                                    {stat.label}
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Connect / Links */}
                    <div className="text-center">
                        <h3
                            className="text-lg font-bold mb-6 text-[var(--color-emerald-900)] dark:text-white"
                            style={{ fontFamily: 'var(--font-serif)' }}
                        >
                            Connect
                        </h3>
                        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 sm:gap-6 flex-wrap">
                            <a
                                href="mailto:advent007@duck.com"
                                className="flex items-center gap-2 px-6 py-3 rounded-xl border border-[var(--color-primary)]/20 dark:border-[var(--color-primary)]/10 bg-white/50 dark:bg-white/[0.02] text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-[var(--color-primary)]/10 hover:border-[var(--color-primary)]/40 hover:text-[var(--color-emerald-800)] dark:hover:text-[var(--color-primary)] transition-all group shadow-sm !no-underline"
                            >
                                <span className="material-symbols-outlined text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] group-hover:scale-110 transition-transform">
                                    mail
                                </span>
                                Email
                            </a>

                            <a
                                href="https://github.com/id-root"
                                target="_blank"
                                rel="noopener noreferrer"
                                className="flex items-center gap-2 px-6 py-3 rounded-xl border border-[var(--color-primary)]/20 dark:border-[var(--color-primary)]/10 bg-white/50 dark:bg-white/[0.02] text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-[var(--color-primary)]/10 hover:border-[var(--color-primary)]/40 hover:text-[var(--color-emerald-800)] dark:hover:text-[var(--color-primary)] transition-all group shadow-sm !no-underline"
                            >
                                <span className="material-symbols-outlined text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] group-hover:scale-110 transition-transform">
                                    code
                                </span>
                                Github
                            </a>

                            <a
                                href="https://portfolio-id-root.vercel.app"
                                target="_blank"
                                rel="noopener noreferrer"
                                className="flex items-center gap-2 px-6 py-3 rounded-xl border border-[var(--color-primary)]/20 dark:border-[var(--color-primary)]/10 bg-white/50 dark:bg-white/[0.02] text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-[var(--color-primary)]/10 hover:border-[var(--color-primary)]/40 hover:text-[var(--color-emerald-800)] dark:hover:text-[var(--color-primary)] transition-all group shadow-sm !no-underline"
                            >
                                <span className="material-symbols-outlined text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] group-hover:scale-110 transition-transform">
                                    language
                                </span>
                                Portfolio
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
