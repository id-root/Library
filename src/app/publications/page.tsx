'use client';

import { useState } from 'react';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import { writeupsMeta } from '@/lib/writeups-data';

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
    const [filter, setFilter] = useState('All');
    
    const tabs = ['All', 'Research', 'Write-up'];

    const filteredWriteups = writeupsMeta.filter((writeup) => {
        if (filter === 'All') return true;
        if (filter === 'Research') return writeup.category === 'Research Paper';
        // Everything else is considered a Write-up
        if (filter === 'Write-up') return writeup.category !== 'Research Paper';
        return true;
    });

    return (
        <div className="pt-24 pb-20 animate-fadeIn">
            <div className="max-w-5xl mx-auto px-6">
                {/* Header */}
                <div className="mb-10 text-center">
                    <p className="text-xs font-semibold tracking-[0.3em] uppercase mb-4 text-[var(--color-gold)]">
                        Research & Write-ups
                    </p>
                    <h1
                        className="text-4xl md:text-5xl font-bold text-[var(--color-emerald-950)] dark:text-white mb-4"
                        style={{ fontFamily: 'var(--font-serif)' }}
                    >
                        Publications
                    </h1>
                    <p className="text-slate-600 dark:text-slate-400 max-w-lg mx-auto font-light mb-8">
                        A collection of cybersecurity write-ups, CTF solutions, and technical deep-dives.
                    </p>
                </div>

                {/* Filter Tabs */}
                <div className="flex justify-center gap-3 sm:gap-6 mb-16 flex-wrap">
                    {tabs.map(tab => (
                        <button
                            key={tab}
                            onClick={() => setFilter(tab)}
                            className={`px-5 py-2 rounded-full text-sm font-semibold transition-all duration-300 ${
                                filter === tab 
                                    ? 'bg-[var(--color-emerald-800)] text-white dark:bg-[var(--color-primary)] dark:text-[var(--color-emerald-900)] shadow-md shadow-[var(--color-emerald-800)]/20' 
                                    : 'bg-[var(--color-primary)]/10 text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] hover:bg-[var(--color-primary)]/20'
                            }`}
                        >
                            {tab}
                        </button>
                    ))}
                </div>

                {/* Cards Grid */}
                <motion.div layout className="grid md:grid-cols-2 gap-8 items-start">
                    <AnimatePresence mode="popLayout">
                        {filteredWriteups.map((writeup) => (
                            <motion.div
                                key={writeup.slug}
                                layout
                                initial={{ opacity: 0, scale: 0.95, y: 10 }}
                                animate={{ opacity: 1, scale: 1, y: 0 }}
                                exit={{ opacity: 0, scale: 0.95, y: 10 }}
                                transition={{ duration: 0.4, type: "spring", bounce: 0.2 }}
                                className="h-full"
                            >
                                <Link
                                    href={`/publications/${writeup.slug}`}
                                    className="group flex flex-col h-full rounded-2xl overflow-hidden border border-[var(--color-primary)]/20 dark:border-[var(--color-primary)]/10 bg-white dark:bg-[var(--color-surface-dark)] hover:border-[var(--color-primary)]/60 dark:hover:border-[var(--color-primary)]/40 transition-all duration-300 hover:shadow-xl hover:shadow-black/5 dark:hover:shadow-black/30"
                                >
                                    {/* Card Header */}
                                    <div className="h-48 relative overflow-hidden bg-gradient-to-br from-[var(--color-emerald-800)] to-[var(--color-emerald-900)]">
                                        <div className="absolute inset-0 opacity-10 pointer-events-none">
                                            {/* Removed the large faint letter since it was buggy and overlapped */}
                                            <div className="absolute bottom-0 right-0 w-48 h-48 rounded-full bg-[var(--color-primary)]/10 translate-x-1/4 translate-y-1/4" />
                                            <div className="absolute top-0 left-1/2 w-32 h-32 rounded-full bg-[var(--color-gold)]/10 -translate-y-1/2" />
                                        </div>

                                        {/* Category & Difficulty badges */}
                                        <div className="absolute top-4 left-4 right-4 flex items-start justify-between z-10">
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
                                        <div className="absolute bottom-0 inset-x-0 h-20 bg-gradient-to-t from-[var(--color-emerald-900)] to-transparent pointer-events-none" />

                                        {/* Title on image */}
                                        <div className="absolute bottom-4 left-6 right-6 z-10">
                                            <h2
                                                className="text-xl font-bold text-white group-hover:text-[var(--color-primary)] transition-colors"
                                                style={{ fontFamily: 'var(--font-serif)' }}
                                            >
                                                {writeup.title}
                                            </h2>
                                        </div>
                                    </div>

                                    {/* Card Body */}
                                    <div className="p-6 flex flex-col flex-1">
                                        <p className="text-sm text-slate-600 dark:text-slate-400 mb-4 line-clamp-3 leading-relaxed flex-1">
                                            {writeup.description}
                                        </p>

                                        {/* Tags */}
                                        <div className="flex flex-wrap gap-2 mb-4">
                                            {writeup.tags.slice(0, 3).map((tag) => (
                                                <span
                                                    key={tag}
                                                    className="text-[11px] px-2.5 py-1 rounded-full bg-[var(--color-primary)]/10 text-[var(--color-emerald-800)] dark:text-[var(--color-primary)] font-medium"
                                                >
                                                    {tag}
                                                </span>
                                            ))}
                                        </div>

                                        {/* Meta */}
                                        <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-500 pt-4 border-t border-[var(--color-primary)]/10 mt-auto">
                                            <span>{writeup.date}</span>
                                            <span>{writeup.readTime}</span>
                                        </div>
                                    </div>
                                </Link>
                            </motion.div>
                        ))}
                    </AnimatePresence>
                </motion.div>
            </div>
        </div>
    );
}
