'use client';

import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeRaw from 'rehype-raw';
import rehypeHighlight from 'rehype-highlight';
import rehypeSlug from 'rehype-slug';
import CodeBlock from './CodeBlock';
import { Components } from 'react-markdown';

interface MarkdownRendererProps {
    content: string;
}

export default function MarkdownRenderer({ content }: MarkdownRendererProps) {
    const components: Components = {
        code({ className, children, ...props }) {
            const match = /language-(\w+)/.exec(className || '');
            const isInline = !match && !className;

            if (isInline) {
                return (
                    <code className="bg-[var(--color-primary)]/15 px-1.5 py-0.5 rounded text-[0.88em] font-[var(--font-mono)] text-[var(--color-emerald-800)] dark:text-[var(--color-primary)]" {...props}>
                        {children}
                    </code>
                );
            }

            return (
                <CodeBlock className={className}>
                    {children}
                </CodeBlock>
            );
        },
        pre({ children }) {
            return <>{children}</>;
        },
        img({ src, alt, ...props }) {
            if (!src) return null;
            // Handle relative image paths
            return (
                <img
                    src={src}
                    alt={alt || ''}
                    className="max-w-full rounded-xl my-6 shadow-lg"
                    {...props}
                />
            );
        },
        table({ children }) {
            return (
                <div className="overflow-x-auto my-6 custom-scrollbar">
                    <table className="w-full border-collapse text-sm">
                        {children}
                    </table>
                </div>
            );
        },
        blockquote({ children }) {
            return (
                <blockquote className="my-6 pl-4 border-l-4 border-[var(--color-primary)] bg-[var(--color-primary)]/5 rounded-r-lg py-3 pr-4 italic text-[var(--color-emerald-900)] dark:text-[var(--color-primary-light)]">
                    {children}
                </blockquote>
            );
        },
    };

    return (
        <div className="prose-article">
            <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                rehypePlugins={[rehypeRaw, rehypeHighlight, rehypeSlug]}
                components={components}
            >
                {content}
            </ReactMarkdown>
        </div>
    );
}
