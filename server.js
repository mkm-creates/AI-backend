import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import fetch from 'node-fetch';
import * as cheerio from 'cheerio';
import cors from 'cors';
import emailApi from './emailApi.js';
import PDFDocument from 'pdfkit';
import { Readable } from 'stream';

const app = express();
const PORT = process.env.PORT || 5000;
app.use(cors());
app.use(emailApi);

// --- AI Summarization Helper ---

const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY ;
const OPENROUTER_API_URL = "https://api.groq.com/openai/v1/chat/completions";
async function aiSummarize(text) {
  try {
    const res = await fetch(OPENROUTER_API_URL, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "meta-llama/llama-4-scout-17b-16e-instruct",
        messages: [
          { role: "system", content: "You are a cybersecurity analyst. Summarize the following news article in 3-5 sentences, focusing on the main threat, affected products, and recommended actions, directly start with the summary and no greeting messages" },
          { role: "user", content: text }
        ],
        // max_tokens: 180
      })
    });
    const data = await res.json();
    if (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) {
      return data.choices[0].message.content.trim();
    }
    return "";
  } catch (err) {
    return "";
  }
}

// --- Helper to fetch full article content ---
async function fetchFullArticle(url, selector) {
  try {
    const res = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const html = await res.text();
    const $ = cheerio.load(html);
    if (selector) {
      return $(selector).text().trim();
    }
    // fallback: get all text
    return $('body').text().trim().slice(0, 3000);
  } catch {
    return "";
  }
}

// --- Helper: Ensure description is at least 6-7 lines and ends with a period ---
function ensureLongDescription(text, fallback = "") {
  if (!text) text = fallback;
  if (!text) return "";
  let lines = text.split('\n').filter(l => l.trim().length > 0);
  if (lines.length < 6) {
    // Try to split into sentences
    const sentences = text.match(/[^.!?]+[.!?]+/g) || [text];
    while (lines.length < 6 && sentences.length > 0) {
      lines.push(sentences.shift());
    }
  }
  let desc = lines.slice(0, 7).join(' ').trim();
  if (!desc.endsWith('.')) desc += '.';
  return desc;
}

// --- Helper: Try to extract CVSS score from text ---
function extractCvss(text) {
  if (!text) return null;
  const match = text.match(/CVSS(?:\s*Score)?[:\s]*([0-9]\.[0-9])/i);
  if (match) {
    const score = parseFloat(match[1]);
    if (!isNaN(score)) return score;
  }
  // Try to find "score X.Y" pattern
  const match2 = text.match(/score\s*([0-9]\.[0-9])/i);
  if (match2) {
    const score = parseFloat(match2[1]);
    if (!isNaN(score)) return score;
  }
  return null;
}

// --- AI Summarization Helper (with in-memory cache for this run) ---
const aiSummaryCache = {};
async function aiSummarizeCached(text, cacheKey) {
  if (aiSummaryCache[cacheKey]) return aiSummaryCache[cacheKey];
  const summary = await aiSummarize(text);
  aiSummaryCache[cacheKey] = summary;
  return summary;
}

// --- Data Sources (updated parse logic for description/cvss) ---
const trustedSources = [
  {
    name: 'The Hacker News',
    url: 'https://thehackernews.com/',
    parse: async ($) =>
      await Promise.all($('.body-post').map(async (i, el) => {
        const title = $(el).find('h2.home-title').text().trim();
        const descRaw = $(el).find('.home-desc').text().trim();
        let url = $(el).find('a.story-link').attr('href');
        let datePublished = new Date().toISOString();
        const meta = $(el).find('.item-label').text().trim();
        if (meta) {
          const parsed = Date.parse(meta);
          if (!isNaN(parsed)) datePublished = new Date(parsed).toISOString();
        }
        let fullContent = await fetchFullArticle(url, '.articlebody');
        let aiSummary = fullContent ? await aiSummarizeCached(fullContent, url) : descRaw;
        let description = ensureLongDescription(fullContent, descRaw || aiSummary);
        let cvssScore = extractCvss(fullContent) || extractCvss(descRaw) || null;
        return {
          id: url,
          cveId: '',
          title,
          description,
          severity: extractSeverity(title + ' ' + descRaw),
          aiSummary: aiSummary || descRaw,
          datePublished,
          source: 'The Hacker News',
          url,
          cvssScore,
          affectedProducts: [],
        };
      }).get()),
  },
  {
    name: 'KrebsOnSecurity',
    url: 'https://krebsonsecurity.com/',
    parse: async ($) =>
      await Promise.all($('.post').map(async (i, el) => {
        const title = $(el).find('h2.entry-title').text().trim();
        let url = $(el).find('a').attr('href');
        const descriptionRaw = $(el).find('.entry-summary').text().trim();
        const datePublished = $(el).find('time').attr('datetime') || new Date().toISOString();
        let fullContent = await fetchFullArticle(url, '.entry-content');
        let aiSummary = fullContent ? await aiSummarizeCached(fullContent, url) : descriptionRaw;
        let description = ensureLongDescription(fullContent, descriptionRaw || aiSummary);
        let cvssScore = extractCvss(fullContent) || extractCvss(descriptionRaw) || null;
        return {
          id: url,
          cveId: '',
          title,
          description,
          severity: extractSeverity(title + ' ' + descriptionRaw),
          aiSummary: aiSummary || descriptionRaw,
          datePublished,
          source: 'KrebsOnSecurity',
          url,
          cvssScore,
          affectedProducts: [],
        };
      }).get()),
  },
  {
    name: 'SecurityWeek',
    url: 'https://www.securityweek.com/cybercrime/',
    parse: async ($) =>
      await Promise.all($('.td_module_10').map(async (i, el) => {
        const title = $(el).find('.entry-title').text().trim();
        let url = $(el).find('a').attr('href');
        const descriptionRaw = $(el).find('.td-excerpt').text().trim();
        const datePublished = $(el).find('.td-post-date').text().trim() || new Date().toISOString();
        let fullContent = await fetchFullArticle(url, '.td-post-content');
        let aiSummary = fullContent ? await aiSummarizeCached(fullContent, url) : descriptionRaw;
        let description = ensureLongDescription(fullContent, descriptionRaw || aiSummary);
        let cvssScore = extractCvss(fullContent) || extractCvss(descriptionRaw) || null;
        return {
          id: url,
          cveId: '',
          title,
          description,
          severity: extractSeverity(title + ' ' + descriptionRaw),
          aiSummary: aiSummary || descriptionRaw,
          datePublished,
          source: 'SecurityWeek',
          url,
          cvssScore,
          affectedProducts: [],
        };
      }).get()),
  },
  {
    name: 'BleepingComputer',
    url: 'https://www.bleepingcomputer.com/',
    parse: async ($) =>
      await Promise.all($('.bc_latest_news .bc_latest_news_item').map(async (i, el) => {
        const title = $(el).find('.bc_latest_news_title').text().trim();
        let url = 'https://www.bleepingcomputer.com' + $(el).find('a').attr('href');
        const descriptionRaw = $(el).find('.bc_latest_news_summary').text().trim();
        const datePublished = $(el).find('.bc_latest_news_date').text().trim() || new Date().toISOString();
        let fullContent = await fetchFullArticle(url, '.articleBody');
        let aiSummary = fullContent ? await aiSummarizeCached(fullContent, url) : descriptionRaw;
        let description = ensureLongDescription(fullContent, descriptionRaw || aiSummary);
        let cvssScore = extractCvss(fullContent) || extractCvss(descriptionRaw) || null;
        return {
          id: url,
          cveId: '',
          title,
          description,
          severity: extractSeverity(title + ' ' + descriptionRaw),
          aiSummary: aiSummary || descriptionRaw,
          datePublished,
          source: 'BleepingComputer',
          url,
          cvssScore,
          affectedProducts: [],
        };
      }).get()),
  },
  // ...add more sources as needed...
];

// --- Severity Helper ---
const extractSeverity = (text) => {
  if (!text) return 'medium';
  const t = text.toLowerCase();
  if (t.includes('critical')) return 'critical';
  if (t.includes('high')) return 'high';
  if (t.includes('medium')) return 'medium';
  if (t.includes('low')) return 'low';
  return 'medium';
};

// --- Main Threats Endpoint (optimized for speed) ---
app.get('/api/threats', async (req, res) => {
  let allNews = [];
  // Limit concurrency for AI calls to avoid lag
  for (const source of trustedSources) {
    try {
      const response = await fetch(source.url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
      const html = await response.text();
      const $ = cheerio.load(html);
      const news = await source.parse($);
      allNews = allNews.concat(news);
    } catch (err) {
      console.error(`Error fetching from ${source.name}:`, err.message);
    }
  }
  // Ensure every threat has a valid date
  allNews = allNews.map(t => ({
    ...t,
    datePublished: t.datePublished && !isNaN(new Date(t.datePublished).getTime())
      ? new Date(t.datePublished).toISOString()
      : new Date().toISOString(),
    description: ensureLongDescription(t.description, t.aiSummary)
  }));
  if (allNews.length === 0) {
    return res.status(500).json({ error: 'Failed to fetch news from all sources' });
  }
  res.json(allNews.slice(0, 40));
});

// Helper to aggregate all threats from all sources (fully async, with AI summaries)
async function getAllThreats() {
  let allNews = [];
  for (const source of trustedSources) {
    try {
      const response = await fetch(source.url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
      const html = await response.text();
      const $ = cheerio.load(html);
      // Await the parsed news (it returns a promise)
      const news = await source.parse($);
      allNews = allNews.concat(news);
    } catch (err) {
      console.error(`Error fetching from ${source.name}:`, err.message);
    }
  }
  // Defensive: filter out undefined/null/empty threats
  allNews = allNews.filter(Boolean);
  allNews = allNews.filter(t => t && t.title && t.description);

  allNews = allNews.map(t => ({
    ...t,
    datePublished: t.datePublished && !isNaN(new Date(t.datePublished).getTime())
      ? new Date(t.datePublished).toISOString()
      : new Date().toISOString(),
    description: ensureLongDescription(t.description, t.aiSummary)
  }));

  return allNews.filter(t => t.datePublished && !isNaN(new Date(t.datePublished).getTime()));
}

// Enhanced PDF generator: include title, date, source, link, AI summary, and description
function generateThreatsPDF(threats, title, res) {
  const doc = new PDFDocument({ margin: 40 });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${title.replace(/\s+/g, '_').toLowerCase()}.pdf"`);
  doc.pipe(res);

  doc.fontSize(20).text(title, { align: 'center' });
  doc.moveDown();
  doc.fontSize(12).text(`Generated: ${new Date().toLocaleString()}`);
  doc.moveDown();

  threats.forEach((threat, idx) => {
    doc.fontSize(14).fillColor('black').text(`${idx + 1}. ${threat.title}`);
    doc.fontSize(11).fillColor('gray').text(`Source: ${threat.source} | Severity: ${threat.severity} | Date: ${threat.datePublished}`);
    if (threat.url) {
      doc.fontSize(11).fillColor('blue').text(`Link: ${threat.url}`, { link: threat.url, underline: true });
    }
    if (threat.aiSummary) {
      doc.fontSize(12).fillColor('black').text(`AI Summary: ${threat.aiSummary}`, {align: 'justify'});
    }
    doc.fontSize(12).fillColor('black').text(`Description: ${threat.description}`, {align: 'justify'});
    doc.moveDown();
    if (doc.y > doc.page.height - 100) doc.addPage();
  });

  doc.end();
}

// --- Weekly Report Endpoint (real news, AI summaries, dates, links) ---
app.get('/api/reports/weekly', async (req, res) => {
  try {
    const allThreats = await getAllThreats();
    const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    // Use only threats from the last 7 days, sorted by date descending
    const weekThreats = allThreats
      .filter(t => new Date(t.datePublished) >= weekAgo)
      .sort((a, b) => new Date(b.datePublished) - new Date(a.datePublished));
    if (!weekThreats.length) {
      res.status(404).json({ error: "No weekly threats found" });
      return;
    }
    generateThreatsPDF(weekThreats, 'Weekly Threat Intelligence Report', res);
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate weekly report', details: err.message });
  }
});

// --- Monthly Report Endpoint (real news, AI summaries, dates, links) ---
app.get('/api/reports/monthly', async (req, res) => {
  try {
    const allThreats = await getAllThreats();
    const monthAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    // Only critical/high, sorted by date descending
    const monthThreats = allThreats
      .filter(t => new Date(t.datePublished) >= monthAgo && (t.severity === 'critical' || t.severity === 'high'))
      .sort((a, b) => new Date(b.datePublished) - new Date(a.datePublished));
    if (!monthThreats.length) {
      res.status(404).json({ error: "No monthly threats found" });
      return;
    }
    generateThreatsPDF(monthThreats, 'Monthly Critical & High Threats Report', res);
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate monthly report', details: err.message });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`ThreatFeed backend running on http://localhost:${PORT}`);
});