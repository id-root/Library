import Link from 'next/link';
import { writeupsMeta } from '@/lib/writeups-loader';

const categoryColors: Record<string, string> = {
    'Network Security': 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300',
    'SSRF & AI Exploitation': 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
    'Network Pivoting': 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
    'Binary Exploitation': 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
    'Research Paper': 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300',
};

const difficultyColors: Record<string, string> = {
    'Medium': 'text-yellow-600 dark:text-yellow-400',
    'Hard': 'text-orange-600 dark:text-orange-400',
    'Insane': 'text-red-600 dark:text-red-400',
};

export default function PublicationsPage() {
    return (
        <div className="pt-24 pb-20 animate-fadeIn">
            <div className="max-w-5xl mx-auto px-6">
                {/* Header */}
                <div className="mb-16 text-center">
                    <p className="text-xs font-semibold tracking-[0.3em] uppercase mb-4 text-[var(--color-gold)]">
                        Research & Write-ups
                    </p>
                    <h1
                        className="text-4xl md:text-5xl font-bold text-[var(--color-emerald-950)] dark:text-white mb-4"
                        style={{ fontFamily: 'var(--font-serif)' }}
                    >
                        Publications
                    </h1>
                    <p className="text-slate-600 dark:text-slate-400 max-w-lg mx-auto font-light">
                        A collection of cybersecurity write-ups, CTF solutions, and technical deep-dives.
                    </p>
                </div>

                {/* Cards Grid */}
                <div className="grid md:grid-cols-2 gap-8">
                    {writeupsMeta.map((writeup) => (
                        <Link
                            key={writeup.slug}
                            href={`/publications/${writeup.slug}`}
                            className="group block rounded-2xl overflow-hidden border border-[var(--color-primary)]/20 dark:border-[var(--color-primary)]/10 bg-white dark:bg-[var(--color-surface-dark)] hover:border-[var(--color-primary)]/60 dark:hover:border-[var(--color-primary)]/40 transition-all duration-300 hover:shadow-xl hover:shadow-black/5 dark:hover:shadow-black/30"
                        >
                            {/* Card Header */}
                            <div className="h-48 relative overflow-hidden bg-gradient-to-br from-[var(--color-emerald-800)] to-[var(--color-emerald-900)]">
                                <div className="absolute inset-0 opacity-10">
                                    <div className="absolute top-4 left-4 text-6xl font-bold text-white/20" style={{ fontFamily: 'var(--font-serif)' }}>
                                        {writeup.title.charAt(0)}
                                    </div>
                                    <div className="absolute bottom-0 right-0 w-48 h-48 rounded-full bg-[var(--color-primary)]/10 translate-x-1/4 translate-y-1/4" />
                                    <div className="absolute top-0 left-1/2 w-32 h-32 rounded-full bg-[var(--color-gold)]/10 -translate-y-1/2" />
                                </div>

                                {/* Category & Difficulty badges */}
                                <div className="absolute top-4 left-4 right-4 flex items-start justify-between">
                                    <span className={`text-xs font-bold px-3 py-1 rounded-full ${categoryColors[writeup.category] || 'bg-slate-100 text-slate-800'}`}>
                                        {writeup.category}
                                    </span>
                                    {writeup.difficulty && (
                                        <span className={`text-xs font-bold ${difficultyColors[writeup.difficulty] || 'text-slate-500'}`}>
                                            {writeup.difficulty}
                                        </span>
                                    )}
                                </div>

                                {/* Decorative bottom gradient */}
                                <div className="absolute bottom-0 inset-x-0 h-16 bg-gradient-to-t from-[var(--color-emerald-900)] to-transparent" />

                                {/* Title on image */}
                                <div className="absolute bottom-4 left-6 right-6">
                                    <h2
                                        className="text-xl font-bold text-white group-hover:text-[var(--color-primary)] transition-colors"
                                        style={{ fontFamily: 'var(--font-serif)' }}
                                    >
                                        {writeup.title}
                                    </h2>
                                </div>
                            </div>

                            {/* Card Body */}
                            <div className="p-6">
                                <p className="text-sm text-slate-600 dark:text-slate-400 mb-4 line-clamp-2 leading-relaxed">
                                    {writeup.description}
                                </p>

                                {/* Tags */}
                                <div className="flex flex-wrap gap-2 mb-4">
                                    {writeup.tags.slice(0, 3).map((tag) => (
                                        <span
                                            key={tag}
                                            className="text-xs px-2.5 py-1 rounded-full bg-[var(--color-primary)]/10 text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] font-medium"
                                        >
                                            {tag}
                                        </span>
                                    ))}
                                </div>

                                {/* Meta */}
                                <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-500 pt-4 border-t border-[var(--color-primary)]/10">
                                    <span>{writeup.date}</span>
                                    <span>{writeup.readTime}</span>
                                </div>
                            </div>
                        </Link>
                    ))}
                </div>
            </div>
        </div>
    );
}
