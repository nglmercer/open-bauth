
import { readdir, stat, readFile, writeFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";

const rootDir = resolve(__dirname, "..");
const outputFile = join(rootDir, "llm.txt");

const EXCLUDES = [
    "node_modules",
    "dist",
    ".git",
    ".github",
    "logs",
    "bun.lock",
    "package-lock.json",
    "yarn.lock",
    ".DS_Store",
    "_navbar.md",
    "_sidebar.md",
    "examples",
    "scripts",
    "tests",
    "llm.txt" // don't include itself if it already exists
];

const INLCUDE_EXTENSIONS = [
    ".md"
];

async function getFiles(dir: string): Promise<string[]> {
    const dirents = await readdir(dir, { withFileTypes: true });
    const files: string[] = [];

    for (const dirent of dirents) {
        const res = join(dir, dirent.name);
        if (EXCLUDES.some(exclude => res.includes(exclude))) {
            continue;
        }

        if (dirent.isDirectory()) {
            files.push(...(await getFiles(res)));
        } else {
            const ext = res.substring(res.lastIndexOf('.'));
            if (INLCUDE_EXTENSIONS.includes(ext) || dirent.name === 'Dockerfile') {
                files.push(res);
            }
        }
    }
    return files;
}

async function generate() {
    console.log("Scanning files...");
    const files = await getFiles(rootDir);
    console.log(`Found ${files.length} files.`);

    let content = "# Project Context\n\n";
    content += `Total files: ${files.length}\n\n`;

    for (const file of files) {
        const relPath = relative(rootDir, file);
        console.log(`Reading ${relPath}...`);
        try {
            const fileContent = await readFile(file, "utf-8");
            content += `\n\n--- FILE: ${relPath} ---\n`;
            content += "```" + (file.split('.').pop() || "") + "\n";
            content += fileContent;
            content += "\n```\n";
        } catch (e) {
            console.error(`Error reading ${relPath}:`, e);
        }
    }

    await writeFile(outputFile, content);
    console.log(`Successfully generated ${outputFile}`);
}

generate().catch(console.error);
