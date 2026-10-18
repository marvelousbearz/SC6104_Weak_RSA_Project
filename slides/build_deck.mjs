import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Presentation, PresentationFile } from "@oai/artifact-tool";

const workspaceDir = "/Users/marvelousbear/Desktop/SC6104_Weak_RSA_Project";
const skillDir = "/Users/marvelousbear/.codex/plugins/cache/openai-primary-runtime/presentations/26.1015.12040/skills/presentations";
const runtimePython = "/Users/marvelousbear/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3";
const outDir = path.join(workspaceDir, "slides");
const stagingDir = path.join(workspaceDir, ".pptx_build");
const finalPath = path.join(outDir, "Weak_RSA_Project_Common_Modulus_Final.pptx");

const C = { bg: "F5F1E8", panel: "FFFFFF", line: "C8D6D1", ink: "18384A", muted: "46616B", dim: "718A8D", red: "167D86", green: "167D86" };
const display = "Georgia";
const body = "Arial";
const mono = "Courier New";
const W = 1280, H = 720;

async function blobToFile(file, blob) {
  await fs.writeFile(file, new Uint8Array(await blob.arrayBuffer()));
}

function box(slide, left, top, width, height, fill = "none", line = "none") {
  return slide.shapes.add({ geometry: "rect", position: { left, top, width, height }, fill, line: { style: "solid", fill: line, width: line === "none" ? 0 : 1 } });
}

function text(slide, value, left, top, width, height, size, color = C.ink, opts = {}) {
  const shape = slide.shapes.add({ geometry: "textbox", position: { left, top, width, height }, fill: "none", line: { style: "solid", fill: "none", width: 0 } });
  shape.text = value;
  shape.text.style = { typeface: opts.mono ? mono : (opts.display ? display : body), fontSize: size, color, bold: !!opts.bold, italic: !!opts.italic, verticalAlignment: opts.valign || "top", alignment: opts.align || "left", insets: 0 };
  return shape;
}

function chrome(slide, number, section = "SC6104 / WEAK RSA") {
  slide.background.fill = C.bg;
  box(slide, 62, 55, 1156, 2, C.ink);
  text(slide, section, 62, 70, 540, 18, 11, C.muted, { mono: true, bold: true });
  text(slide, "TIME", 1000, 70, 48, 18, 11, C.muted, { mono: true, bold: true, align: "right" });
  text(slide, "08:00", 1057, 65, 92, 26, 18, C.red, { mono: true, bold: true, align: "right" });
  text(slide, String(number).padStart(2, "0"), 1165, 70, 53, 18, 12, C.muted, { mono: true, align: "right", bold: true });
  box(slide, 62, 655, 1156, 1, C.line);
  text(slide, "SC6104 CRYPTOGRAPHY", 62, 667, 400, 17, 12, C.muted, { mono: true });
}

function title(slide, value, subtitle, number) {
  chrome(slide, number);
  text(slide, "SC6104 CRYPTOGRAPHY COURSE PROJECT", 62, 100, 600, 20, 13, C.red, { mono: true, bold: true });
  text(slide, value, 62, 152, 740, 180, 62, C.ink, { display: true, bold: true });
  text(slide, subtitle, 66, 365, 625, 70, 24, C.muted);
}

function bullet(slide, label, bodyText, y, red = false) {
  box(slide, 84, y + 10, 9, 9, red ? C.red : C.dim);
  text(slide, label, 112, y, 270, 26, 21, C.ink, { bold: true });
  text(slide, bodyText, 112, y + 30, 620, 52, 17, C.muted);
}

function addNotes(slide, source) {
  if (slide.notes && typeof slide.notes.add === "function") slide.notes.add(source);
}

async function main() {
  await fs.mkdir(outDir, { recursive: true });
  await fs.mkdir(stagingDir, { recursive: true });
  const deck = Presentation.create({ slideSize: { width: W, height: H } });

  // 1. Cover
  { const s = deck.slides.add();
    title(s, "Breaking\nWeak RSA Keys", "Two controlled attacks show why large moduli cannot compensate for faulty key generation.", 1);
    text(s, "Same N, different e", 835, 184, 340, 35, 26, C.ink, { display: true, bold: true });
    text(s, "a·e₁ + b·e₂ = 1", 835, 236, 350, 52, 31, C.red, { mono: true, bold: true });
    box(s, 835, 310, 330, 1, C.line);
    text(s, "Small d: Wiener attack", 835, 340, 340, 35, 26, C.ink, { display: true, bold: true });
    text(s, "d < N^(1/4) / 3", 835, 392, 350, 52, 31, C.red, { mono: true, bold: true });
    text(s, "8-minute presentation with live local demo", 66, 522, 550, 24, 16, C.dim, { mono: true });
    text(s, "ZHANG LIXIANG  ·  PAI LINGWEI", 66, 558, 550, 24, 18, C.red, { mono: true, bold: true });
  }

  // 2. Threat model
  { const s = deck.slides.add(); chrome(s, 2, "THREAT MODEL");
    text(s, "Threat model", 62, 100, 600, 60, 44, C.ink, { display: true, bold: true });
    text(s, "The attacker receives public keys only", 64, 166, 620, 34, 24, C.muted);
    bullet(s, "Known to attacker", "Two public keys (N, e1), (N, e2) and two ciphertexts for one message.", 238, true);
    bullet(s, "Not attempted", "No generic factorization of a correctly generated 2048-bit RSA modulus.", 332);
    bullet(s, "Goal", "Recover the message when an implementation reuses N incorrectly.", 426);
    box(s, 786, 214, 330, 250, C.panel, C.line);
    text(s, "PUBLIC", 824, 254, 230, 22, 14, C.dim, { mono: true, bold: true });
    text(s, "(N, e₁), (N, e₂)", 824, 290, 260, 45, 28, C.ink, { mono: true, bold: true });
    text(s, "same N\nsame message", 824, 360, 230, 60, 22, C.red, { bold: true });
    addNotes(s, "All evidence comes from keys generated by this project.");
  }

  // 3. Common modulus
  { const s = deck.slides.add(); chrome(s, 3, "ATTACK 1 / COMMON MODULUS");
    text(s, "Same N, different e", 62, 100, 700, 60, 44, C.ink, { display: true, bold: true });
    text(s, "Reusing one RSA modulus for the same message leaks that message", 64, 166, 760, 34, 22, C.muted);
    box(s, 85, 250, 310, 154, C.panel, C.line); box(s, 514, 250, 310, 154, C.panel, C.line);
    text(s, "c₁ = m^e₁ mod N", 126, 286, 235, 42, 27, C.ink, { mono: true, bold: true });
    text(s, "c₂ = m^e₂ mod N", 555, 286, 235, 42, 27, C.ink, { mono: true, bold: true });
    text(s, "same N, same m", 198, 350, 145, 24, 17, C.red, { mono: true }); text(s, "gcd(e₁, e₂) = 1", 614, 350, 170, 24, 17, C.red, { mono: true });
    text(s, "a·e₁ + b·e₂ = 1", 190, 475, 900, 68, 46, C.red, { mono: true, bold: true, align: "center" });
    text(s, "Then c₁ᵃ · c₂ᵇ = m mod N", 338, 555, 600, 28, 21, C.muted, { align: "center" });
  }

  // 4. Live demo mechanics
  { const s = deck.slides.add(); chrome(s, 4, "DEMO / COMMON MODULUS");
    text(s, "Live demonstration", 62, 100, 700, 60, 44, C.ink, { display: true, bold: true });
    text(s, "The attack program sees only public parameters", 64, 166, 720, 34, 22, C.muted);
    const lines = ["1. Generate four 2048-bit public keys", "2. Reuse one N with coprime e₁ and e₂", "3. Index the collection by N", "4. Use Extended Euclid to recover the message"];
    lines.forEach((line, i) => { box(s, 84, 240 + i * 73, 8, 44, i === 2 ? C.red : C.dim); text(s, line, 116, 239 + i * 73, 720, 30, 24, i === 2 ? C.ink : C.muted, { bold: i === 2 }); });
    box(s, 857, 227, 302, 300, C.panel, C.line);
    text(s, "TERMINAL OUTPUT", 885, 255, 230, 20, 13, C.dim, { mono: true });
    text(s, "indexed scan found\n1 same-N pair\n\nRecovered plaintext:\nNever reuse an\nRSA modulus", 885, 295, 240, 170, 18, C.ink, { mono: true });
    addNotes(s, "Demo command: python3 -m src.demo --bits 2048");
  }

  // 5. Wiener theory
  { const s = deck.slides.add(); chrome(s, 5, "ATTACK 2 / WIENER");
    text(s, "Wiener's small-d attack", 62, 100, 800, 60, 44, C.ink, { display: true, bold: true });
    text(s, "A private exponent chosen too small creates a continued-fraction shortcut", 64, 166, 850, 34, 22, C.muted);
    text(s, "e × d − k × φ(N) = 1", 90, 264, 620, 56, 34, C.ink, { mono: true, bold: true });
    text(s, "When d is small, k / d approximates e / N", 90, 345, 620, 34, 23, C.muted);
    text(s, "continued fractions produce candidate values for d", 90, 411, 620, 34, 23, C.muted);
    box(s, 796, 244, 360, 226, C.panel, C.line);
    text(s, "CLASSICAL SUFFICIENT\nVULNERABILITY RANGE", 832, 275, 250, 45, 15, C.dim, { mono: true, bold: true });
    text(s, "d < N^(1/4) / 3", 823, 356, 290, 42, 30, C.red, { mono: true, bold: true, align: "center" });
    text(s, "We verify candidates by reconstructing p and q", 276, 548, 730, 28, 20, C.muted, { align: "center" });
  }

  // 6. Wiener demo
  { const s = deck.slides.add(); chrome(s, 6, "DEMO / WIENER");
    text(s, "Second live attack", 62, 100, 700, 60, 44, C.ink, { display: true, bold: true });
    text(s, "A 2048-bit modulus still fails when d is intentionally tiny", 64, 166, 760, 34, 22, C.muted);
    box(s, 88, 246, 280, 172, C.panel, C.line); box(s, 498, 246, 280, 172, C.panel, C.line); box(s, 908, 246, 280, 172, C.panel, C.line);
    text(s, "PUBLIC KEY", 116, 276, 220, 20, 14, C.dim, { mono: true }); text(s, "N, e", 116, 323, 220, 38, 32, C.ink, { mono: true, bold: true });
    text(s, "CONVERGENTS", 526, 276, 220, 20, 14, C.dim, { mono: true }); text(s, "k / d", 526, 323, 220, 38, 32, C.ink, { mono: true, bold: true });
    text(s, "RECOVERED", 936, 276, 220, 20, 14, C.dim, { mono: true }); text(s, "d, p, q", 936, 323, 220, 38, 32, C.red, { mono: true, bold: true });
    text(s, "The demo verifies the recovered d by decrypting a second message", 174, 504, 930, 32, 23, C.muted, { align: "center" });
  }

  // 7. Experiments, native editable charts
  { const s = deck.slides.add(); chrome(s, 7, "EXPERIMENTS");
    text(s, "Measured controlled experiments", 62, 100, 850, 60, 44, C.ink, { display: true, bold: true });
    text(s, "Timings regenerate each run on locally generated vulnerable keys", 64, 166, 820, 34, 22, C.muted);
    const common = await fs.readFile(path.join(workspaceDir, "results/common_modulus_benchmark.csv"), "utf8");
    const wiener = await fs.readFile(path.join(workspaceDir, "results/wiener_results.csv"), "utf8");
    const parse = csv => csv.trim().split("\n").slice(1).map(line => line.split(","));
    const commonRows = parse(common), wienerRows = parse(wiener);
    text(s, "Same-N collection scan", 75, 225, 400, 24, 18, C.ink, { bold: true });
    text(s, "Wiener recovery", 675, 225, 400, 24, 18, C.ink, { bold: true });
    s.charts.add("bar", { position: { left: 75, top: 250, width: 515, height: 280 }, categories: commonRows.map(row => row[0]), series: [{ name: "Naive pairs", values: commonRows.map(row => Math.round(Number(row[1]))), fill: C.ink }, { name: "Indexed by N", values: commonRows.map(row => Math.round(Number(row[2]))), fill: C.red }], hasLegend: true, textStyle: { typeface: body, fontSize: 13, fill: C.muted }, xAxis: { title: "Public keys", textStyle: { typeface: body, fontSize: 12, fill: C.muted } }, yAxis: { title: "microseconds", textStyle: { typeface: body, fontSize: 12, fill: C.muted }, majorGridlines: { style: "solid", fill: C.line, width: 1 } } });
    s.charts.add("bar", { position: { left: 675, top: 250, width: 515, height: 280 }, categories: wienerRows.map(row => row[0]), series: [{ name: "Recovery microseconds", values: wienerRows.map(row => Math.round(Number(row[2]) * 1000)), fill: C.red }], hasLegend: false, textStyle: { typeface: body, fontSize: 13, fill: C.muted }, xAxis: { title: "Modulus bits", textStyle: { typeface: body, fontSize: 12, fill: C.muted } }, yAxis: { title: "microseconds", textStyle: { typeface: body, fontSize: 12, fill: C.muted }, majorGridlines: { style: "solid", fill: C.line, width: 1 } } });
    text(s, "Results are workload-dependent. The security conclusion comes from the successful key recovery, not a universal runtime claim.", 76, 562, 1110, 42, 16, C.dim);
    addNotes(s, "Source: results generated by experiments/run_experiments.py on this machine.");
  }

  // 8. Conclusion
  { const s = deck.slides.add(); chrome(s, 8, "CONCLUSION");
    text(s, "Large RSA keys still need correct generation", 62, 100, 1030, 116, 52, C.ink, { display: true, bold: true });
    bullet(s, "Use reviewed libraries", "Avoid custom key-generation code in production systems.", 260, true);
    bullet(s, "Never reuse N", "Each RSA key pair needs its own independently generated modulus.", 352);
    bullet(s, "Avoid manual d selection", "RSA parameters require validated mathematical constraints.", 444);
    text(s, "Key length protects against generic factoring. It cannot repair modulus reuse or unsafe parameters.", 82, 554, 1050, 40, 24, C.red, { bold: true });
  }

  const candidate = path.join(stagingDir, "candidate.pptx");
  await (await PresentationFile.exportPptx(deck)).save(candidate);
  const { finalizePresentation } = await import(pathToFileURL(path.join(skillDir, "container_tools/artifact_tool_utils.mjs")).href);
  await finalizePresentation({
    workspaceDir,
    candidatePath: candidate,
    finalPath,
    pythonExecutable: runtimePython,
    integrityValidatorPath: path.join(skillDir, "container_tools/inspect_presentation_package_integrity.py"),
    layoutValidatorPath: path.join(skillDir, "container_tools/inspect_presentation_layout_geometry.py"),
    layoutArgs: ["--expected-slide-size-emu", "12192000,6858000", "--validate-bullet-geometry", "--validate-heading-fit"],
    explicitTotalSlideCount: 8,
    requiredNativeChartOwnerSlides: [7],
    requiredNativeTableOwnerSlides: [],
    materializeLiteralChartWorkbooks: true,
    fontPolicy: { basis: "design", families: [display, body, mono, "Aptos"] },
    verifyArtifactToolImport: true,
    receiptPath: path.join(stagingDir, "Weak_RSA_Project_Common_Modulus_Final.validation.json"),
  });
  for (const [index, slide] of deck.slides.items.entries()) {
    await blobToFile(path.join(stagingDir, `slide-${String(index + 1).padStart(2, "0")}.png`), await deck.export({ slide, format: "png", scale: 1 }));
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });

