import { loadWriteupContent, getAllSlugs, getWriteupMetaBySlug } from '@/lib/writeups-loader';
import ArticleClient from './ArticleClient';

interface PageProps {
    params: Promise<{ slug: string }>;
}

export async function generateStaticParams() {
    return getAllSlugs().map(slug => ({ slug }));
}

export default async function ArticlePage({ params }: PageProps) {
    const { slug } = await params;
    const data = loadWriteupContent(slug);

    if (!data) {
        return (
            <div className="pt-24 pb-20 text-center">
                <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Write-up not found</h1>
            </div>
        );
    }

    return <ArticleClient meta={data.meta} markdownSections={data.markdownSections} />;
}
