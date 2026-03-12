'use client';

import { useState, useEffect, useMemo, useRef } from 'react';
import { motion, useScroll, useSpring } from 'framer-motion';
import MarkdownRenderer from '@/components/MarkdownRenderer';

interface WriteupMeta {
    slug: string;
    title: string;
    category: string;
    tags: string[];
    description: string;
    readTime: string;
    date: string;
    difficulty: string;
}

interface ArticleClientProps {
    meta: WriteupMeta;
    markdownSections: { title: string; content: string }[];
}

interface HeadingInfo {
    id: string;
    text: string;
    level: number;
}

export default function ArticleClient({ meta, markdownSections }: ArticleClientProps) {
    const [activeTab, setActiveTab] = useState(0);
    const [activeHeadingId, setActiveHeadingId] = useState<string>('');
    const tocNavRef = useRef<HTMLDivElement>(null);

    // Smooth reading progress
    const { scrollYProgress } = useScroll();
    const scaleX = useSpring(scrollYProgress, {
        stiffness: 100,
        damping: 30,
        restDelta: 0.001
    });

    // Extract headings from markdown
    const headings = useMemo(() => {
        const content = markdownSections[activeTab].content;
        const matches = [...content.matchAll(/^(#{1,3})\s+(.+)$/gm)];
        const slugCounts: Record<string, number> = {};

        return matches.map((m) => {
            const rawText = m[2].trim();
            // Clean up markdown syntax for the TOC label
            const text = rawText
                .replace(/!\[.*?\]\(.*?\)/g, '')
                .replace(/\[(.*?)\]\(.*?\)/g, '$1')
                .replace(/[*`_]/g, '')
                .replace(/<[^>]*>/g, '') // remove html tags if any
                .trim();

            // Generate slug exactly as github-slugger does (what rehype-slug uses)
            let id = text.toLowerCase()
                .replace(/[^\w\s-]/g, '')
                .trim()
                .replace(/[-\s]+/g, '-');

            if (!id) id = 'heading';

            // Handle duplicate IDs
            if (slugCounts[id]) {
                slugCounts[id]++;
                id = `${id}-${slugCounts[id] - 1}`;
            } else {
                slugCounts[id] = 1;
            }

            return {
                level: m[1].length,
                text,
                id
            };
        });
    }, [activeTab, markdownSections]);

    // Track active heading on scroll
    useEffect(() => {
        if (headings.length === 0) return;

        const handleObserveHeadings = () => {
            const scrollPosition = window.scrollY + 100; // Offset for navbar

            // Find the last heading that is above the current scroll position
            let current = headings[0].id;
            for (const { id } of headings) {
                const element = document.getElementById(id);
                if (element && element.offsetTop <= scrollPosition) {
                    current = id;
                } else if (element && element.offsetTop > scrollPosition) {
                    break;
                }
            }
            setActiveHeadingId(current);
        };

        window.addEventListener('scroll', handleObserveHeadings);
        handleObserveHeadings();
        return () => window.removeEventListener('scroll', handleObserveHeadings);
    }, [headings]);

    // Auto-scroll TOC to keep active heading in view
    useEffect(() => {
        if (!activeHeadingId || !tocNavRef.current) return;

        const activeLink = tocNavRef.current.querySelector(`[href="#${activeHeadingId}"]`);
        if (activeLink) {
            activeLink.scrollIntoView({
                behavior: 'smooth',
                block: 'nearest',
                inline: 'nearest'
            });
        }
    }, [activeHeadingId]);

    return (
        <>
            {/* Reading Progress Bar - Fixed at top of viewport */}
            <div className="fixed top-0 left-0 w-full h-[4px] bg-transparent z-[99999]">
                <motion.div
                    className="h-full bg-[var(--color-emerald-800)] dark:bg-[var(--color-primary)] shadow-sm origin-left"
                    style={{ scaleX }}
                />
            </div>

            <div className="animate-fadeIn">
                <main className="pt-24 pb-20">
                {/* Hero Banner — All metadata merged in */}
                <div className="max-w-[1200px] mx-auto px-6 mb-12">
                    <div className="relative w-full max-w-[960px] rounded-2xl overflow-hidden shadow-xl group">
                        <div className="absolute inset-0 bg-gradient-to-br from-[var(--color-emerald-800)] to-[var(--color-emerald-900)]">
                            <div className="absolute inset-0 opacity-20 grain-overlay mix-blend-overlay pointer-events-none" />
                            <div className="absolute top-0 right-0 w-72 h-72 rounded-full bg-[var(--color-primary)]/5 -translate-y-1/2 translate-x-1/4" />
                            <div className="absolute bottom-0 left-0 w-56 h-56 rounded-full bg-[var(--color-gold)]/5 translate-y-1/3 -translate-x-1/4" />
                        </div>

                        <div className="relative z-10 px-8 sm:px-12 py-12 sm:py-16 flex flex-col justify-end min-h-[280px] sm:min-h-[320px]">
                            {/* Top row: Category + Difficulty */}
                            <div className="flex items-center gap-3 mb-6 flex-wrap">
                                <span className="text-xs font-bold px-3 py-1 rounded-full bg-white/15 text-white/90 uppercase tracking-wider backdrop-blur-sm">
                                    {meta.category}
                                </span>
                                {meta.difficulty && (
                                    <span className="text-xs font-bold px-3 py-1 rounded-full bg-[var(--color-gold)]/20 text-[var(--color-gold)] uppercase tracking-wider">
                                        {meta.difficulty}
                                    </span>
                                )}
                            </div>

                            {/* Title */}
                            <h1
                                className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl font-bold text-white leading-[1.1] mb-6"
                                style={{ fontFamily: 'var(--font-serif)' }}
                            >
                                {meta.title}
                            </h1>

                            {/* Tags */}
                            <div className="flex flex-wrap gap-2 mb-8">
                                {meta.tags.slice(0, 4).map((tag) => (
                                    <span
                                        key={tag}
                                        className="text-[11px] px-2.5 py-1 rounded-full bg-white/10 text-white/70 font-medium backdrop-blur-sm"
                                    >
                                        {tag}
                                    </span>
                                ))}
                            </div>

                            {/* Bottom row: Author + Date + Read time */}
                            <div className="flex items-center gap-4 pt-6 border-t border-white/10">
                                <div className="w-10 h-10 rounded-full bg-white/15 ring-2 ring-[var(--color-primary)]/30 flex items-center justify-center backdrop-blur-sm">
                                    <span className="text-white font-bold text-sm" style={{ fontFamily: 'var(--font-serif)' }}>R</span>
                                </div>
                                <div className="flex flex-col">
                                    <span className="text-sm font-bold text-white/90">Researcher</span>
                                    <span className="text-xs text-white/50 font-medium">{meta.date}</span>
                                </div>
                                <div className="ml-auto flex items-center gap-1.5 text-xs text-white/50 font-medium">
                                    <span className="material-symbols-outlined text-sm">schedule</span>
                                    {meta.readTime}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Multi-part tabs (if more than 1 section) */}
                {markdownSections.length > 1 && (
                    <div className="max-w-[1200px] mx-auto px-6 mb-8">
                        <div className="flex gap-2 overflow-x-auto custom-scrollbar pb-2 max-w-[960px]">
                            {markdownSections.map((section, idx) => (
                                <button
                                    key={idx}
                                    onClick={() => {
                                        setActiveTab(idx);
                                        window.scrollTo({ top: 0, behavior: 'smooth' });
                                    }}
                                    className={`px-4 py-2 rounded-lg text-sm font-medium whitespace-nowrap transition-all ${activeTab === idx
                                        ? 'bg-[var(--color-emerald-800)] text-white shadow-lg'
                                        : 'bg-[var(--color-primary)]/10 text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] hover:bg-[var(--color-primary)]/20'
                                        }`}
                                >
                                    {section.title}
                                </button>
                            ))}
                        </div>
                    </div>
                )}

                {/* Content Layout: Article (Left) + Sidebar (Right) */}
                <div className="max-w-[1200px] mx-auto px-6">
                    <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_280px] gap-12 lg:gap-24 items-start">

                        {/* Main Content */}
                        <article className="min-w-0 w-full prose-article-container">
                            {/* Mobile TOC */}
                            {headings.length > 0 && (
                                <div className="block lg:hidden mb-12">
                                    <details className="bg-white/50 dark:bg-white/[0.02] border border-[var(--color-primary)]/20 rounded-xl overflow-hidden group">
                                        <summary className="px-6 py-4 text-sm font-bold uppercase tracking-wider text-[var(--color-emerald-900)] dark:text-[var(--color-primary)] cursor-pointer list-none flex items-center justify-between hover:bg-[var(--color-primary)]/5 transition-colors">
                                            Table of Contents
                                            <span className="material-symbols-outlined transition-transform duration-300 group-open:rotate-180">expand_more</span>
                                        </summary>
                                        <div className="px-6 pb-6 pt-2 text-sm max-h-80 overflow-y-auto custom-scrollbar">
                                            <nav className="flex flex-col gap-3">
                                                {headings.map((heading) => (
                                                    <a
                                                        key={`mobile-${heading.id}`}
                                                        href={`#${heading.id}`}
                                                        className="text-slate-600 dark:text-slate-400 hover:text-[var(--color-emerald-800)] dark:hover:text-[var(--color-primary)] transition-colors block leading-snug"
                                                        style={{ paddingLeft: `${(heading.level - 1) * 1}rem` }}
                                                    >
                                                        {heading.text}
                                                    </a>
                                                ))}
                                            </nav>
                                        </div>
                                    </details>
                                </div>
                            )}

                            <MarkdownRenderer content={markdownSections[activeTab].content} />

                            {/* Tags */}
                            <div className="mt-12 pt-8 border-t border-[var(--color-primary)]/20 flex flex-wrap gap-4">
                                {meta.tags.map((tag) => (
                                    <span
                                        key={tag}
                                        className="px-4 py-1.5 rounded-full bg-slate-100 dark:bg-slate-800 text-sm font-medium text-slate-600 dark:text-slate-400 hover:bg-[var(--color-primary)]/20 hover:text-[var(--color-emerald-900)] dark:hover:text-[var(--color-primary)] transition-colors cursor-pointer"
                                    >
                                        #{tag.replace(/\s+/g, '')}
                                    </span>
                                ))}
                            </div>
                        </article>

                        {/* Sticky Sidebar - Desktop TOC */}
                        <aside className="hidden lg:block sticky top-32 order-last w-[280px] self-start">
                            <div className="max-h-[calc(100vh-8rem)] overflow-y-auto custom-scrollbar pb-8 pl-4" ref={tocNavRef}>
                                <h3 className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500 mb-6">
                                    Table of Contents
                                </h3>

                                {headings.length > 0 ? (
                                    <nav className="flex flex-col relative before:absolute before:inset-y-0 before:left-0 before:w-px before:bg-black/10 dark:before:bg-white/10">
                                        {headings.map((heading) => {
                                            const isActive = activeHeadingId === heading.id;
                                            return (
                                                <a
                                                    key={heading.id}
                                                    href={`#${heading.id}`}
                                                    className={`relative text-[13px] py-1.5 transition-colors duration-200 block truncate ${isActive
                                                        ? 'text-[var(--color-emerald-900)] dark:text-[var(--color-primary)] font-bold'
                                                        : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
                                                        }`}
                                                    style={{
                                                        paddingLeft: `${(heading.level - 1) * 0.75 + 1}rem`,
                                                    }}
                                                    title={heading.text}
                                                >
                                                    {isActive && (
                                                        <span className="absolute left-[-1px] top-1/2 -translate-y-1/2 w-[2px] h-4 bg-[var(--color-emerald-900)] dark:bg-[var(--color-primary)] rounded-r-full" />
                                                    )}
                                                    {heading.text}
                                                </a>
                                            );
                                        })}
                                    </nav>
                                ) : (
                                    <p className="text-sm text-slate-500 italic">No headings found.</p>
                                )}
                            </div>
                        </aside>

                    </div>
                </div>
            </main>
            </div>
        </>
    );
}
