import fs from 'fs';
import path from 'path';

export interface WriteupMeta {
    slug: string;
    title: string;
    category: string;
    tags: string[];
    description: string;
    readTime: string;
    date: string;
    difficulty: string;
    files: { name: string; path: string; imageBasePath: string }[];
}

export const writeupsMeta: WriteupMeta[] = [
    {
        slug: 'breachblocker-unlocker',
        title: 'BreachBlocker Unlocker',
        category: 'Network Security',
        tags: ['Flask Exploitation', 'OTP Brute Force', 'Crypto'],
        description: 'A multi-phase CTF challenge involving reconnaissance, custom hash cracking, credential extraction, and OTP brute-forcing to capture all 3 flags.',
        readTime: '15 min read',
        date: 'Dec 2025',
        difficulty: 'Medium',
        files: [
            { name: 'Main Writeup', path: 'BreachBlocker-Unlocker/README.md', imageBasePath: '/images/writeups/breachblocker/' },
            { name: 'Decryption Key Analysis', path: 'BreachBlocker-Unlocker/Key-for-BreachBlocker-Unlocker.md', imageBasePath: '/images/writeups/breachblocker/' },
        ],
    },
    {
        slug: 'carrotbane-of-my-existence',
        title: 'Carrotbane of My Existence',
        category: 'SSRF & AI Exploitation',
        tags: ['SSRF', 'DNS Poisoning', 'Prompt Injection', 'Pivoting'],
        description: 'A comprehensive exploitation chain from SSRF vulnerability discovery through DNS poisoning, phishing, AI prompt injection, and internal network pivoting to capture all 4 flags.',
        readTime: '25 min read',
        date: 'Dec 2025',
        difficulty: 'Hard',
        files: [
            { name: 'Main Writeup', path: 'Carrotbane-of-My-Existence/README.md', imageBasePath: '/images/writeups/carrotbane/' },
            { name: 'Decryption Key Analysis', path: 'Carrotbane-of-My-Existence/Key-for-Carrotbane-of-My-Existence.md', imageBasePath: '/images/writeups/carrotbane/' },
        ],
    },
    {
        slug: 'hoppers-origin',
        title: "Hopper's Origin",
        category: 'Network Pivoting',
        tags: ['Privilege Escalation', 'Active Directory', 'Pivoting', 'LDAP'],
        description: 'A massive multi-stage network penetration write-up covering AI prompt injection, SSH pivoting, Active Directory exploitation, Kerberoasting, and domain controller compromise across 6+ machines.',
        readTime: '40 min read',
        date: 'Jan 2026',
        difficulty: 'Insane',
        files: [
            { name: 'Main Writeup', path: 'Hoppers-Origin-Writeup/README.md', imageBasePath: '/images/writeups/hoppers-origin/' },
        ],
    },
    {
        slug: 'scheme-catcher',
        title: 'Scheme Catcher',
        category: 'Binary Exploitation',
        tags: ['Reverse Engineering', 'Heap Exploitation', 'FSOP', 'GDB'],
        description: 'An insane-difficulty two-part binary exploitation challenge involving XOR-encrypted ELF analysis, hidden HTTP paths, Use-After-Free, Tcache poisoning, and House of Apple 2 FSOP RCE.',
        readTime: '30 min read',
        date: 'Dec 2025',
        difficulty: 'Insane',
        files: [
            { name: 'Part 1 — Binary Analysis', path: 'Scheme-Catcher/README.md', imageBasePath: '/images/writeups/scheme-catcher/' },
            { name: 'Part 2 — Heap Exploitation', path: 'Scheme-Catcher/Scheme-Catcher-part-2.md', imageBasePath: '/images/writeups/scheme-catcher/' },
        ],
    },
    {
        slug: 'anti-debug-framework',
        title: 'User-Space Anti-Debug Framework',
        category: 'Research Paper',
        tags: ['Anti-debugging', 'Reverse Engineering', 'Timing Analysis', 'eBPF'],
        description: 'A comprehensive research framework for user-space anti-debug and anti-instrumentation detection on x86_64 Linux systems.',
        readTime: '15 min read',
        date: 'Feb 2026',
        difficulty: '',
        files: [
            { name: 'Research Paper', path: 'research.md', imageBasePath: '/images/writeups/anti-debug/' },
        ],
    },
];

// The base directory where raw writeup markdown files live
const WRITEUPS_DIR = path.join(process.cwd(), '..'); // parent of website/ = library/

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
