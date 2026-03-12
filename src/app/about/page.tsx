'use client';

import { motion } from 'framer-motion';

export default function AboutPage() {
    // Animation variants
    const containerVariants = {
        hidden: { opacity: 0 },
        show: {
            opacity: 1,
            transition: {
                staggerChildren: 0.15,
            },
        },
    };

    const itemVariants = {
        hidden: { opacity: 0, y: 30 },
        show: { 
            opacity: 1, 
            y: 0, 
            transition: { 
                type: 'spring' as const, 
                stiffness: 100,
                damping: 20
            } 
        },
    };

    return (
        <div className="pt-24 pb-20 relative overflow-hidden">
            {/* Background elements */}
            <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-[var(--color-primary)]/5 rounded-full blur-[100px] -translate-y-1/2 translate-x-1/4 pointer-events-none" />
            <div className="absolute bottom-0 left-0 w-[600px] h-[600px] bg-[var(--color-emerald-800)]/5 dark:bg-[var(--color-primary)]/5 rounded-full blur-[120px] translate-y-1/3 -translate-x-1/4 pointer-events-none" />

            <div className="max-w-4xl mx-auto px-6 relative z-10">
                {/* Header */}
                <motion.div 
                    initial={{ opacity: 0, y: -20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.6, ease: 'easeOut' }}
                    className="mb-20 text-center"
                >
                    <motion.p 
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 0.2, duration: 0.8 }}
                        className="text-xs font-semibold tracking-[0.4em] uppercase mb-6 text-[var(--color-gold)]"
                    >
                        Behind the Archive
                    </motion.p>
                    <h1
                        className="text-5xl md:text-7xl font-bold text-[var(--color-emerald-950)] dark:text-white mb-8 tracking-tight"
                        style={{ fontFamily: 'var(--font-serif)' }}
                    >
                        About <span className="text-[var(--color-primary)] italic">Me</span>
                    </h1>
                    <motion.div 
                        initial={{ scaleX: 0 }}
                        animate={{ scaleX: 1 }}
                        transition={{ delay: 0.4, duration: 0.8, ease: 'circOut' }}
                        className="w-24 h-[2px] bg-gradient-to-r from-transparent via-[var(--color-primary)] to-transparent mx-auto" 
                    />
                </motion.div>

                {/* Content */}
                <motion.div 
                    variants={containerVariants}
                    initial="hidden"
                    animate="show"
                    className="relative"
                >
                    {/* Avatar & Intro */}
                    <motion.div variants={itemVariants} className="flex flex-col items-center mb-20">
                        <div className="relative group mb-8">
                            <div className="absolute inset-0 bg-[var(--color-primary)]/20 rounded-full blur-xl group-hover:blur-2xl transition-all duration-500" />
                            <div className="w-32 h-32 relative z-10 rounded-full bg-gradient-to-br from-[var(--color-emerald-800)] to-[var(--color-emerald-950)] flex items-center justify-center ring-2 ring-[var(--color-primary)]/30 group-hover:ring-[var(--color-primary)]/60 shadow-2xl transition-all duration-500">
                                <div className="absolute inset-0 bg-[url('/noise.png')] opacity-20 mix-blend-overlay rounded-full" />
                                <span className="material-symbols-outlined text-6xl text-[var(--color-primary)] group-hover:scale-110 transition-transform duration-500 drop-shadow-[0_0_10px_rgba(var(--color-primary-rgb),0.5)]">
                                    person
                                </span>
                            </div>
                        </div>
                        <p className="text-center text-xl md:text-2xl text-slate-700 dark:text-slate-300 max-w-2xl leading-relaxed font-light">
                            Hii I am <span className="font-semibold text-[var(--color-emerald-900)] dark:text-[var(--color-primary)]">Vector</span>. Waiting for AGI... Exploring cybersecurity, automation, and open‑source learning not to arrive but to continue...
                        </p>
                    </motion.div>

                    {/* Stats */}
                    <motion.div variants={itemVariants} className="grid grid-cols-2 lg:grid-cols-3 gap-6 mb-20">
                        {[
                            { value: '4+', label: 'Write-ups Published', icon: 'auto_stories' },
                            { value: '15+', label: 'Flags Captured', icon: 'flag' },
                            { value: 'CTF', label: 'Competitions', icon: 'emoji_events' },
                        ].map((stat, i) => (
                            <motion.div 
                                key={stat.label} 
                                whileHover={{ scale: 1.05, y: -5 }}
                                className={`text-center p-8 rounded-2xl bg-white/40 dark:bg-white/[0.02] backdrop-blur-xl border border-[var(--color-primary)]/20 dark:border-white/10 shadow-lg hover:shadow-2xl transition-all duration-300 relative group ${i === 2 ? 'col-span-2 lg:col-span-1' : ''}`}
                            >
                                <div className="absolute inset-0 bg-gradient-to-br from-[var(--color-primary)]/5 to-[var(--color-primary)]/0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-2xl" />
                                <span className="material-symbols-outlined text-4xl text-[var(--color-emerald-800)]/60 dark:text-[var(--color-primary)]/60 absolute right-3 top-3 transform rotate-12 group-hover:rotate-0 group-hover:text-[var(--color-primary)] transition-all duration-500">
                                    {stat.icon}
                                </span>
                                <div
                                    className="text-4xl md:text-5xl font-bold text-[var(--color-emerald-800)] dark:text-white mb-3 relative z-10"
                                    style={{ fontFamily: 'var(--font-serif)' }}
                                >
                                    {stat.value}
                                </div>
                                <div className="text-xs md:text-sm text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-widest relative z-10">
                                    {stat.label}
                                </div>
                            </motion.div>
                        ))}
                    </motion.div>

                    {/* Philosophy */}
                    <motion.div variants={itemVariants} className="relative z-10 mb-20">
                        <div className="absolute inset-0 bg-gradient-to-r from-[var(--color-primary)]/0 via-[var(--color-primary)]/5 to-[var(--color-primary)]/0 blur-xl" />
                        <blockquote className="text-center text-2xl md:text-3xl relative py-10 px-10 border-y border-[var(--color-primary)]/20 text-[var(--color-emerald-900)] dark:text-white leading-relaxed font-light" style={{ fontFamily: 'var(--font-serif)' }}>
                            <span className="text-5xl text-[var(--color-primary)] opacity-60 select-none align-top leading-none mr-1" style={{ fontFamily: 'Georgia, serif' }}>&ldquo;</span>
                            The best way to understand a system&apos;s security is to think like the adversary.
                            Every vulnerability tells a story — my <span className="italic text-[var(--color-primary)]">white-papers</span> are those stories, documented.<span className="text-5xl text-[var(--color-primary)] opacity-60 select-none align-bottom leading-none ml-1" style={{ fontFamily: 'Georgia, serif' }}>&rdquo;</span>
                        </blockquote>
                    </motion.div>

                    {/* Skills Section */}
                    <motion.div variants={itemVariants} className="mb-24">
                        <h2 className="text-3xl font-bold text-center mb-12 text-[var(--color-emerald-950)] dark:text-white" style={{ fontFamily: 'var(--font-serif)' }}>
                            Core Expertise
                        </h2>
                        <div className="grid md:grid-cols-2 gap-6">
                            {[
                                { icon: 'shield', title: 'Offensive Security', desc: 'Penetration testing, red teaming, vulnerability assessment, and exploit development. Experienced in CTF competitions and real-world security assessments.' },
                                { icon: 'memory', title: 'Binary Exploitation', desc: 'Reverse engineering, heap exploitation, ROP chains, FSOP, and modern mitigation bypass techniques. Deep knowledge of ELF internals and glibc.' },
                                { icon: 'lan', title: 'Network Security', desc: 'Network pivoting, Active Directory attacks, SSRF exploitation, DNS poisoning, and multi-stage network penetration across complex environments.' },
                                { icon: 'code', title: 'Development', desc: 'Python, Rust, C/C++, Assembly. Building custom exploit tools, reverse engineering frameworks, and security automation scripts.' }
                            ].map((skill, index) => (
                                <motion.div 
                                    key={skill.title}
                                    whileHover={{ scale: 1.02 }}
                                    className="p-8 rounded-2xl border border-[var(--color-primary)]/20 dark:border-white/10 bg-white/40 dark:bg-white/[0.02] backdrop-blur-md hover:bg-white/60 dark:hover:bg-white/[0.04] transition-all duration-300 relative group overflow-hidden"
                                >
                                    <div className="absolute top-0 left-0 w-1 h-full bg-[var(--color-primary)] transform scale-y-0 group-hover:scale-y-100 transition-transform duration-300 origin-top" />
                                    <span className="material-symbols-outlined text-3xl text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] mb-4 block group-hover:scale-110 transition-transform">
                                        {skill.icon}
                                    </span>
                                    <h3
                                        className="text-xl font-bold mb-3 text-[var(--color-emerald-900)] dark:text-white group-hover:text-[var(--color-emerald-800)] dark:group-hover:text-[var(--color-primary)] transition-colors"
                                        style={{ fontFamily: 'var(--font-serif)' }}
                                    >
                                        {skill.title}
                                    </h3>
                                    <p className="text-sm md:text-base text-slate-600 dark:text-slate-400 leading-relaxed">
                                        {skill.desc}
                                    </p>
                                </motion.div>
                            ))}
                        </div>
                    </motion.div>

                    {/* Connect / Links */}
                    <motion.div variants={itemVariants} className="text-center mb-12">
                        <h3
                            className="text-2xl font-bold mb-8 text-[var(--color-emerald-900)] dark:text-white"
                            style={{ fontFamily: 'var(--font-serif)' }}
                        >
                            Let's Connect
                        </h3>
                        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 sm:gap-6 flex-wrap">
                            {[
                                { icon: 'mail', label: 'Email', href: 'mailto:advent007@duck.com' },
                                { icon: 'code', label: 'Github', href: 'https://github.com/id-root' },
                                { icon: 'language', label: 'Portfolio', href: 'https://catalog-id-root.vercel.app' }
                            ].map((link) => (
                                <motion.a
                                    key={link.label}
                                    whileHover={{ scale: 1.05 }}
                                    whileTap={{ scale: 0.95 }}
                                    href={link.href}
                                    target={link.label !== 'Email' ? "_blank" : undefined}
                                    rel={link.label !== 'Email' ? "noopener noreferrer" : undefined}
                                    className="flex items-center gap-3 px-8 py-4 rounded-full border border-[var(--color-primary)]/30 dark:border-white/10 bg-gradient-to-br from-white/60 to-white/20 dark:from-white/5 dark:to-transparent backdrop-blur-md text-sm font-semibold text-slate-700 dark:text-slate-300 hover:text-[var(--color-emerald-900)] dark:hover:text-white shadow-lg hover:shadow-[var(--color-primary)]/20 transition-all group !no-underline relative overflow-hidden"
                                >
                                    <span className="absolute inset-0 bg-[var(--color-primary)]/10 dark:bg-[var(--color-primary)]/20 transform translate-y-full group-hover:translate-y-0 transition-transform duration-300 rounded-full" />
                                    <span className="material-symbols-outlined relative z-10 text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] group-hover:rotate-12 transition-transform duration-300">
                                        {link.icon}
                                    </span>
                                    <span className="relative z-10 tracking-wider uppercase">{link.label}</span>
                                </motion.a>
                            ))}
                        </div>
                    </motion.div>
                </motion.div>
            </div>
        </div>
    );
}
