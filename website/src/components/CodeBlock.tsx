'use client';

import { useState, useRef, ReactNode } from 'react';

interface CodeBlockProps {
    children: ReactNode;
    className?: string; // e.g. "hljs language-python"
}

export default function CodeBlock({ children, className }: CodeBlockProps) {
    const [copied, setCopied] = useState(false);
    const codeRef = useRef<HTMLPreElement>(null);

    // Extract language name roughly from hljs class name like "language-python"
    const langMatch = className?.match(/language-(\w+)/);
    const language = langMatch ? langMatch[1] : '';

    const handleCopy = async () => {
        const text = codeRef.current?.innerText || '';
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        }
    };

    return (
        <div className="relative group my-8 rounded-xl overflow-hidden shadow-2xl shadow-black/40 bg-[#1e1e1e] ring-1 ring-white/10">
            {/* Top Bar matching image */}
            <div className="flex items-center justify-between px-4 py-3 bg-[#1e1e1e] border-b border-white/5">
                <div className="font-mono text-xs text-slate-500 font-medium tracking-wide">
                    {language ? `${language}_code` : 'code_snippet'}
                </div>

                <div className="flex items-center gap-4">
                    <button
                        onClick={handleCopy}
                        className="flex items-center gap-1.5 px-2 py-1 text-xs font-medium rounded bg-white/5 hover:bg-white/10 text-slate-300 transition-colors opacity-0 group-hover:opacity-100"
                        title="Copy code"
                    >
                        <span className="material-symbols-outlined text-[14px]">
                            {copied ? 'check' : 'content_copy'}
                        </span>
                        {copied ? 'Copied' : 'Copy'}
                    </button>
                    <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full bg-[#ff5f56]" />
                        <div className="w-3 h-3 rounded-full bg-[#ffbd2e]" />
                        <div className="w-3 h-3 rounded-full bg-[#27c93f]" />
                    </div>
                </div>
            </div>

            {/* Code Area */}
            <div className="p-4 overflow-x-auto custom-scrollbar">
                <pre className="!mt-0 !mb-0 bg-transparent">
                    <code ref={codeRef} className={`${className || ''} block text-[0.85rem] leading-[1.6] font-[var(--font-mono)] text-slate-300`}>
                        {children}
                    </code>
                </pre>
            </div>
        </div>
    );
}
