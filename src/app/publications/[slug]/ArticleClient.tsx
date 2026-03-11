'use client';

import { useState, useEffect, useMemo } from 'react';
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
    const [readProgress, setReadProgress] = useState(0);
    const [activeTab, setActiveTab] = useState(0);
    const [activeHeadingId, setActiveHeadingId] = useState<string>('');

    // Update reading progress
    useEffect(() => {
        const handleScroll = () => {
            const scrollTop = window.scrollY || document.documentElement.scrollTop || document.body.scrollTop;
            const scrollHeight = document.documentElement.scrollHeight || document.body.scrollHeight;
            const clientHeight = document.documentElement.clientHeight || window.innerHeight;

            const totalHeight = scrollHeight - clientHeight;
            const progress = totalHeight > 0 ? (scrollTop / totalHeight) * 100 : 0;
            setReadProgress(Math.min(progress, 100));
        };

        window.addEventListener('scroll', handleScroll, { passive: true });
        // Trigger once to set initial state
        handleScroll();
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

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

    return (
        <>
            {/* Reading Progress Bar - Fixed at top of viewport */}
            <div className="fixed top-0 left-0 w-full h-[4px] bg-transparent z-[99999]">
                <div
                    className="h-full bg-[var(--color-emerald-800)] dark:bg-[var(--color-primary)] transition-all duration-75 ease-out shadow-sm"
                    style={{ width: `${readProgress}%` }}
                />
            </div>

            <div className="animate-fadeIn">
                <main className="pt-24 pb-20">
                {/* Hero Section */}
                <div className="max-w-[1200px] mx-auto px-6 mb-12">
                    {/* Tags */}
                    <div className="flex items-center gap-3 mb-6 text-xs font-semibold tracking-wider uppercase text-[var(--color-emerald-800)] dark:text-[var(--color-primary)]">
                        <span className="bg-[var(--color-primary)]/20 px-3 py-1 rounded-full">
                            {meta.category}
                        </span>
                        <span className="text-slate-400 dark:text-slate-600">•</span>
                        <span>{meta.difficulty}</span>
                    </div>

                    {/* Title */}
                    <h1
                        className="text-4xl md:text-5xl lg:text-6xl font-bold text-[var(--color-emerald-950)] dark:text-white leading-[1.1] mb-8 max-w-[960px]"
                        style={{ fontFamily: 'var(--font-serif)' }}
                    >
                        {meta.title}
                    </h1>

                    {/* Author Metadata */}
                    <div className="flex items-center gap-4 mb-10 border-b border-[var(--color-primary)]/20 pb-8 max-w-[960px]">
                        <div className="w-12 h-12 rounded-full overflow-hidden bg-[var(--color-emerald-800)] ring-2 ring-[var(--color-primary)]/30 flex items-center justify-center">
                            <span className="text-white font-bold text-lg" style={{ fontFamily: 'var(--font-serif)' }}>R</span>
                        </div>
                        <div className="flex flex-col">
                            <span className="text-sm font-bold text-[var(--color-emerald-900)] dark:text-white">Researcher</span>
                            <span className="text-sm text-slate-500 font-medium">{meta.date}</span>
                        </div>
                        <div className="ml-auto text-sm text-slate-500 font-medium hidden sm:block">
                            {meta.readTime}
                        </div>
                    </div>

                    {/* Featured Banner */}
                    <div className="relative w-full max-w-[960px] aspect-[21/9] rounded-2xl overflow-hidden shadow-xl mb-12 group">
                        <div className="absolute inset-0 bg-gradient-to-br from-[var(--color-emerald-800)] to-[var(--color-emerald-900)]">
                            <div className="absolute inset-0 opacity-20 grain-overlay mix-blend-overlay pointer-events-none" />
                            <div className="absolute inset-0 flex items-center justify-center">
                                <div className="text-center">
                                    <span className="material-symbols-outlined text-6xl text-[var(--color-primary)]/40">
                                        terminal
                                    </span>
                                    <p
                                        className="text-[var(--color-primary)]/60 text-xl mt-2 font-light"
                                        style={{ fontFamily: 'var(--font-serif)' }}
                                    >
                                        {meta.category}
                                    </p>
                                </div>
                            </div>
                            <div className="absolute top-0 right-0 w-72 h-72 rounded-full bg-[var(--color-primary)]/5 -translate-y-1/2 translate-x-1/4" />
                            <div className="absolute bottom-0 left-0 w-56 h-56 rounded-full bg-[var(--color-gold)]/5 translate-y-1/3 -translate-x-1/4" />
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
                        <aside className="hidden lg:block relative order-last w-[280px]">
                            <div className="sticky top-32 max-h-[calc(100vh-8rem)] overflow-y-auto custom-scrollbar pb-8 pl-4">
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
