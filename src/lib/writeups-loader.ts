import fs from 'fs';
import path from 'path';

import { WriteupMeta, writeupsMeta } from './writeups-data';

// The base directory where raw writeup markdown files live
const WRITEUPS_DIR = path.join(process.cwd(), 'data');

export function getWriteupMetaBySlug(slug: string): WriteupMeta | undefined {
    return writeupsMeta.find(w => w.slug === slug);
}

export function loadWriteupContent(slug: string): { meta: WriteupMeta; markdownSections: { title: string; content: string }[] } | null {
    const meta = getWriteupMetaBySlug(slug);
    if (!meta) return null;

    const sections = meta.files.map(file => {
        const filePath = path.join(WRITEUPS_DIR, file.path);
        try {
            let content = fs.readFileSync(filePath, 'utf-8');

            // Fix image paths: replace relative markdown images like ![](image.png) with absolute paths
            content = content.replace(
                /!\[([^\]]*)\]\((?!http|\/)((?:[^)]*\/)?([^)]+\.(png|jpg|jpeg|gif|svg|webp)))\)/gi,
                (match, alt, fullPath, filename, ext) => {
                    // Strip any leading directory paths like "10-Write-ups/..." since images are in public/
                    return `![${alt}](${file.imageBasePath}${filename})`;
                }
            );

            // Also fix markdown-style links that point to other writeup files (like ![Key](Key-file.md))
            // Keep them as-is but remove the image syntax since they're not images
            content = content.replace(
                /!\[([^\]]*)\]\(([^)]+\.md)\)/gi,
                (match, alt, mdPath) => `**${alt}**`
            );

            return { title: file.name, content };
        } catch {
            return { title: file.name, content: `*File not found: ${file.path}*` };
        }
    });

    return { meta, markdownSections: sections };
}

export function getAllSlugs(): string[] {
    return writeupsMeta.map(w => w.slug);
}
