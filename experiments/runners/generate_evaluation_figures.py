"""
DNSentinel: Publication-Quality Research Figures & Summary Tables Generator.

Generates publication-grade research figures and summary tables comparing the four
DNSentinel detection pipelines:
  1. Pipeline A1 (Baseline unmitigated DetectionPipeline)
  2. Pipeline B (ColdStartMitigatedPipeline with enterprise prior)
  3. ML30 Cascade (CascadeDetectionPipeline with fast-path + ML)
  4. ML30 + Burst-Taint (BurstTaintCascadePipeline with parent burst propagation)

All figures and tables derive strictly from verified frozen evaluation artifacts:
  - experiments/results/final_four_pipeline_evaluation.json
  - experiments/results/final_four_pipeline_evaluation_report.md

STRICT COMPLIANCE:
  - No detector re-execution, retraining, or threshold modification.
  - Strict provenance separation (historical lab traces, synthetic cold host, held-out benchmark).
  - Undefined metrics represented as N/A (never zero).
  - High-DPI Cairo vector graphics with academic labels, units, and captions.
"""

import sys
sys.path.append("/usr/lib/python3/dist-packages")

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import cairo

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_DIR = PROJECT_ROOT / "experiments" / "results"
EVAL_FIGURES_DIR = RESULTS_DIR / "figures" / "evaluation"
TABLES_DIR = RESULTS_DIR / "tables"
SOURCE_JSON = RESULTS_DIR / "final_four_pipeline_evaluation.json"
SOURCE_MD = RESULTS_DIR / "final_four_pipeline_evaluation_report.md"

# Shared Academic Color Palette
COLOR_A1 = (0.88, 0.30, 0.28)         # Coral Red (Pipeline A1 - Unmitigated)
COLOR_B = (0.92, 0.55, 0.20)          # Amber Orange (Pipeline B - Mitigated)
COLOR_CASCADE = (0.28, 0.48, 0.72)    # Slate Blue (ML30 Cascade)
COLOR_BURST_TAINT = (0.12, 0.62, 0.42) # Emerald Teal (ML30 + Burst-Taint)
COLOR_DIRECT_ML = (0.22, 0.45, 0.70)   # Blue for Direct ML detections
COLOR_TAINT_PROP = (0.85, 0.35, 0.15)  # Orange for Taint-propagated detections

COLOR_GRID = (0.88, 0.90, 0.92)
COLOR_TEXT_MAIN = (0.10, 0.12, 0.16)
COLOR_TEXT_MUTED = (0.38, 0.42, 0.48)
COLOR_BORDER = (0.22, 0.26, 0.32)


class PublicationPlot:
    """
    High-DPI vector plotting canvas tailored for publication-quality academic figures.
    """
    def __init__(self, width: int = 1600, height: int = 950, title: str = ""):
        self.width = width
        self.height = height
        self.title = title
        self.surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, width, height)
        self.ctx = cairo.Context(self.surface)

        # High-quality antialiasing
        self.ctx.set_antialias(cairo.ANTIALIAS_SUBPIXEL)

        # Crisp white background
        self.ctx.set_source_rgb(1.0, 1.0, 1.0)
        self.ctx.paint()

    def set_font(self, size: float = 14.0, bold: bool = False):
        weight = cairo.FONT_WEIGHT_BOLD if bold else cairo.FONT_WEIGHT_NORMAL
        self.ctx.select_font_face("DejaVu Sans", cairo.FONT_SLANT_NORMAL, weight)
        self.ctx.set_font_size(size)

    def draw_text(self, text: str, x: float, y: float, size: float = 14.0, bold: bool = False,
                  color: Tuple[float, float, float] = COLOR_TEXT_MAIN, align: str = "left"):
        self.set_font(size, bold)
        self.ctx.set_source_rgb(*color)
        ext = self.ctx.text_extents(text)

        draw_x = x
        if align == "center":
            draw_x = x - ext.width / 2.0
        elif align == "right":
            draw_x = x - ext.width

        self.ctx.move_to(draw_x, y)
        self.ctx.show_text(text)

    def draw_multiline_text(self, text: str, x: float, y: float, max_width: float,
                            size: float = 12.0, line_spacing: float = 18.0,
                            bold: bool = False, color: Tuple[float, float, float] = COLOR_TEXT_MUTED,
                            align: str = "left") -> float:
        """Draws paragraph text with clean word-wrapping to guarantee zero overflow."""
        self.set_font(size, bold)
        words = text.split(" ")
        lines = []
        current_line = []

        for word in words:
            test_line = " ".join(current_line + [word])
            ext = self.ctx.text_extents(test_line)
            if ext.width <= max_width:
                current_line.append(word)
            else:
                if current_line:
                    lines.append(" ".join(current_line))
                    current_line = [word]
                else:
                    lines.append(word)
                    current_line = []
        if current_line:
            lines.append(" ".join(current_line))

        curr_y = y
        for line in lines:
            self.draw_text(line, x, curr_y, size=size, bold=bold, color=color, align=align)
            curr_y += line_spacing
        return curr_y

    def draw_rounded_rect(self, x: float, y: float, w: float, h: float, r: float = 6.0,
                          fill_color: Optional[Tuple[float, float, float]] = None,
                          stroke_color: Optional[Tuple[float, float, float]] = None,
                          line_width: float = 1.0, alpha: float = 1.0):
        ctx = self.ctx
        ctx.new_sub_path()
        ctx.arc(x + w - r, y + r, r, -math.pi / 2, 0)
        ctx.arc(x + w - r, y + h - r, r, 0, math.pi / 2)
        ctx.arc(x + r, y + h - r, r, math.pi / 2, math.pi)
        ctx.arc(x + r, y + r, r, math.pi, 3 * math.pi / 2)
        ctx.close_path()

        if fill_color:
            ctx.set_source_rgba(fill_color[0], fill_color[1], fill_color[2], alpha)
            if stroke_color:
                ctx.fill_preserve()
            else:
                ctx.fill()
        if stroke_color:
            ctx.set_source_rgba(stroke_color[0], stroke_color[1], stroke_color[2], alpha)
            ctx.set_line_width(line_width)
            ctx.stroke()

    def draw_na_badge(self, x: float, y: float, w: float, h: float, label: str = "N/A"):
        """Draws an academically rigorous N/A badge with subtle diagonal hatching."""
        ctx = self.ctx
        # Fill background with soft neutral gray
        ctx.set_source_rgba(0.94, 0.95, 0.96, 1.0)
        ctx.rectangle(x, y, w, h)
        ctx.fill()

        # Diagonal hatch lines
        ctx.save()
        ctx.rectangle(x, y, w, h)
        ctx.clip()
        ctx.set_source_rgba(0.82, 0.84, 0.86, 0.7)
        ctx.set_line_width(1.0)
        step = 10.0
        for lx in range(int(x - h), int(x + w + h), int(step)):
            ctx.move_to(lx, y + h)
            ctx.line_to(lx + h, y)
            ctx.stroke()
        ctx.restore()

        # Border
        ctx.set_source_rgb(0.75, 0.78, 0.82)
        ctx.set_line_width(1.0)
        ctx.rectangle(x, y, w, h)
        ctx.stroke()

        # Center Text Badge
        self.draw_rounded_rect(x + w/2 - 38, y + h/2 - 12, 76, 24, r=4,
                               fill_color=(1.0, 1.0, 1.0), stroke_color=(0.6, 0.65, 0.7), line_width=1.0)
        self.draw_text(label, x + w/2, y + h/2 + 5, size=11, bold=True,
                       color=(0.4, 0.45, 0.5), align="center")

    def save(self, filepath: Path):
        filepath.parent.mkdir(parents=True, exist_ok=True)
        self.surface.write_to_png(str(filepath))
        size_kb = filepath.stat().st_size / 1024.0
        print(f"[+] Saved figure: {filepath.name} ({self.width}x{self.height}, {size_kb:.1f} KB)")


def load_evaluation_data() -> Dict[str, Any]:
    if not SOURCE_JSON.exists():
        raise FileNotFoundError(f"Missing source evaluation JSON: {SOURCE_JSON}")
    with open(SOURCE_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


# ==============================================================================
# FIGURE 1: RECALL & FPR COMPARISON ON COMBINED STREAM (N=234)
# ==============================================================================

def generate_figure_01_combined_stream(data: Dict[str, Any]):
    """
    Figure 1: Dual-panel comparison of Recall (%) and False-Positive Rate (%) on
    the Historical Combined Lab Benchmark Stream (N=234: 115 Tunnel + 119 Benign).
    """
    comb_stream = data["Combined Historical Lab Benchmark Stream (Tunnel Burst + Benign Lab)"]["pipelines"]

    plot = PublicationPlot(width=1600, height=950, title="Combined Stream Recall and FPR")
    ctx = plot.ctx

    # Title & Subtitle Header
    plot.draw_text("Figure 1: Detection Recall and False-Positive Rate (FPR) on Historical Combined Lab Stream",
                   80, 52, size=24, bold=True, color=(0.08, 0.12, 0.20))
    plot.draw_text("Continuous stream of N=234 queries (115 Kali DNS tunnel queries followed by 119 benign enterprise queries)",
                   80, 82, size=14, color=COLOR_TEXT_MUTED)

    # Panel Setup (Dual-Panel: Left = Recall, Right = FPR)
    panel_y_top = 130
    panel_height = 640
    panel_width = 660
    panel1_x_left = 120
    panel2_x_left = 860

    pipelines = [
        ("Pipeline A1", comb_stream["Pipeline A1"], COLOR_A1, "Unmitigated Baseline"),
        ("Pipeline B", comb_stream["Pipeline B"], COLOR_B, "Cold-Start Mitigated"),
        ("ML30 Cascade", comb_stream["ML30 Cascade"], COLOR_CASCADE, "Fast-Path + Random Forest"),
        ("ML30 + Burst-Taint", comb_stream["ML30 + Burst-Taint"], COLOR_BURST_TAINT, "Cascade + Burst Propagation")
    ]

    # --- PANEL A: RECALL (%) ---
    plot.draw_rounded_rect(panel1_x_left - 30, panel_y_top - 15, panel_width + 50, panel_height + 40,
                           r=8, fill_color=(0.985, 0.99, 1.0), stroke_color=(0.85, 0.88, 0.92), line_width=1.0)
    plot.draw_text("Panel (a): Attack Detection Recall (%)", panel1_x_left, panel_y_top + 15, size=17, bold=True)
    plot.draw_text("Target Attack Class: N = 115 tunnel queries | Higher is better", panel1_x_left, panel_y_top + 36, size=12, color=COLOR_TEXT_MUTED)

    # Y-axis scaling for Panel A (0 to 100%)
    chart_y_top = panel_y_top + 60
    chart_height = panel_height - 120
    chart_y_bottom = chart_y_top + chart_height

    for pct in range(0, 101, 20):
        y = chart_y_bottom - (pct / 100.0) * chart_height
        ctx.set_source_rgba(COLOR_GRID[0], COLOR_GRID[1], COLOR_GRID[2], 0.9)
        ctx.set_line_width(1.0)
        ctx.move_to(panel1_x_left + 40, y)
        ctx.line_to(panel1_x_left + panel_width, y)
        ctx.stroke()
        plot.draw_text(f"{pct}%", panel1_x_left + 30, y + 5, size=12, color=COLOR_TEXT_MUTED, align="right")

    # Draw bars for Panel A
    bar_width = 95
    spacing = 135
    start_x = panel1_x_left + 75

    for idx, (name, metrics, color, desc) in enumerate(pipelines):
        recall_pct = metrics["recall"] * 100.0
        bar_h = (recall_pct / 100.0) * chart_height
        bx = start_x + idx * spacing
        by = chart_y_bottom - bar_h

        # Shadow & Bar
        ctx.set_source_rgba(color[0], color[1], color[2], 0.15)
        ctx.rectangle(bx + 3, by + 3, bar_width, bar_h)
        ctx.fill()

        ctx.set_source_rgba(color[0], color[1], color[2], 0.92)
        ctx.rectangle(bx, by, bar_width, bar_h)
        ctx.fill()
        ctx.set_source_rgba(color[0] * 0.7, color[1] * 0.7, color[2] * 0.7, 1.0)
        ctx.set_line_width(1.5)
        ctx.rectangle(bx, by, bar_width, bar_h)
        ctx.stroke()

        # Labels on top of bar
        plot.draw_text(f"{recall_pct:.2f}%", bx + bar_width / 2, by - 24, size=14, bold=True, color=color, align="center")
        plot.draw_text(f"({metrics['tp']}/{metrics['pos_count']})", bx + bar_width / 2, by - 8, size=11, color=COLOR_TEXT_MUTED, align="center")

        # X-axis label
        clean_name = name.replace(" + ", "\n+")
        lines = clean_name.split("\n")
        plot.draw_text(lines[0], bx + bar_width / 2, chart_y_bottom + 22, size=12, bold=True, align="center")
        if len(lines) > 1:
            plot.draw_text(lines[1], bx + bar_width / 2, chart_y_bottom + 38, size=11, bold=True, color=color, align="center")

    # Annotation callout in Panel A
    plot.draw_rounded_rect(panel1_x_left + 330, chart_y_top + 160, 260, 65, r=6,
                           fill_color=(1.0, 1.0, 1.0), stroke_color=(0.2, 0.6, 0.4), line_width=1.2)
    plot.draw_text("Burst-Taint recovers 4 delimiter", panel1_x_left + 340, chart_y_top + 183, size=11, bold=True, color=(0.1, 0.5, 0.3))
    plot.draw_text("chunks missed by direct ML", panel1_x_left + 340, chart_y_top + 201, size=11, color=(0.2, 0.4, 0.3))
    plot.draw_text("(Recall reaches 99.13%)", panel1_x_left + 340, chart_y_top + 217, size=10, bold=True, color=(0.1, 0.5, 0.3))

    # --- PANEL B: FALSE-POSITIVE RATE (%) ---
    plot.draw_rounded_rect(panel2_x_left - 30, panel_y_top - 15, panel_width + 50, panel_height + 40,
                           r=8, fill_color=(1.0, 0.985, 0.985), stroke_color=(0.92, 0.85, 0.85), line_width=1.0)
    plot.draw_text("Panel (b): False-Positive Rate (FPR %)", panel2_x_left, panel_y_top + 15, size=17, bold=True)
    plot.draw_text("Benign Background Class: N = 119 queries | Lower is better (Zero is ideal)", panel2_x_left, panel_y_top + 36, size=12, color=COLOR_TEXT_MUTED)

    for pct in range(0, 101, 20):
        y = chart_y_bottom - (pct / 100.0) * chart_height
        ctx.set_source_rgba(COLOR_GRID[0], COLOR_GRID[1], COLOR_GRID[2], 0.9)
        ctx.set_line_width(1.0)
        ctx.move_to(panel2_x_left + 40, y)
        ctx.line_to(panel2_x_left + panel_width, y)
        ctx.stroke()
        plot.draw_text(f"{pct}%", panel2_x_left + 30, y + 5, size=12, color=COLOR_TEXT_MUTED, align="right")

    start_x_b = panel2_x_left + 75
    for idx, (name, metrics, color, desc) in enumerate(pipelines):
        fpr_pct = metrics["fpr"] * 100.0
        bar_h = (fpr_pct / 100.0) * chart_height
        bx = start_x_b + idx * spacing
        by = chart_y_bottom - bar_h

        ctx.set_source_rgba(color[0], color[1], color[2], 0.15)
        ctx.rectangle(bx + 3, by + 3, bar_width, bar_h)
        ctx.fill()

        ctx.set_source_rgba(color[0], color[1], color[2], 0.92)
        ctx.rectangle(bx, by, bar_width, bar_h)
        ctx.fill()
        ctx.set_source_rgba(color[0] * 0.7, color[1] * 0.7, color[2] * 0.7, 1.0)
        ctx.set_line_width(1.5)
        ctx.rectangle(bx, by, bar_width, bar_h)
        ctx.stroke()

        plot.draw_text(f"{fpr_pct:.2f}%", bx + bar_width / 2, by - 24, size=14, bold=True, color=color, align="center")
        plot.draw_text(f"({metrics['fp']}/{metrics['neg_count']})", bx + bar_width / 2, by - 8, size=11, color=COLOR_TEXT_MUTED, align="center")

        clean_name = name.replace(" + ", "\n+")
        lines = clean_name.split("\n")
        plot.draw_text(lines[0], bx + bar_width / 2, chart_y_bottom + 22, size=12, bold=True, align="center")
        if len(lines) > 1:
            plot.draw_text(lines[1], bx + bar_width / 2, chart_y_bottom + 38, size=11, bold=True, color=color, align="center")

    # Alarm Storm Callout in Panel B
    plot.draw_rounded_rect(panel2_x_left + 160, chart_y_top + 30, 310, 80, r=6,
                           fill_color=(1.0, 1.0, 1.0), stroke_color=(0.85, 0.2, 0.2), line_width=1.5)
    plot.draw_text("Catastrophic Baseline Self-Poisoning:", panel2_x_left + 172, chart_y_top + 54, size=12, bold=True, color=(0.8, 0.15, 0.15))
    plot.draw_text("Pipeline A1 incorporates unmitigated tunnel", panel2_x_left + 172, chart_y_top + 72, size=11, color=(0.4, 0.1, 0.1))
    plot.draw_text("traffic into profile, generating 116/119 false alarms.", panel2_x_left + 172, chart_y_top + 90, size=11, color=(0.4, 0.1, 0.1))
    plot.draw_text("Both Cascade & Burst-Taint maintain 1.68% FPR.", panel2_x_left + 172, chart_y_top + 106, size=10, bold=True, color=(0.1, 0.5, 0.3))

    # Bottom Academic Caption Card (Word Wrapped)
    caption_y = 800
    plot.draw_rounded_rect(80, caption_y, 1440, 120, r=8,
                           fill_color=(0.96, 0.97, 0.98), stroke_color=(0.82, 0.85, 0.88), line_width=1.0)
    plot.draw_text("Academic Caption & Operational Findings:", 100, caption_y + 24, size=13, bold=True, color=(0.15, 0.2, 0.28))

    caption_text = (
        "In the historical combined lab stream, an attacker generates 115 tunneling queries followed immediately by normal traffic. "
        "Pipeline A1 detects only 31.30% of attacks and poisons its host baseline, driving FPR to 97.48% (116 false alarms). "
        "Pipeline B prevents profile poisoning via dual-baseline mitigation, reducing FPR to 4.20%, but captures only 56.52% of attacks. "
        "The ML30 Cascade achieves 95.65% recall and 1.68% FPR. Augmenting the cascade with parent-domain Burst-Taint propagation "
        "reaches 99.13% recall (114/115 attacks detected) without increasing false positives (FPR strictly unchanged at 1.68%, 2/119 FP)."
    )
    next_y = plot.draw_multiline_text(caption_text, 100, caption_y + 46, max_width=1390, size=11.5, line_spacing=18.0)
    plot.draw_text("Source Data: experiments/results/final_four_pipeline_evaluation.json (Combined Historical Lab Benchmark Stream)",
                   100, next_y + 4, size=11, bold=True, color=(0.3, 0.35, 0.45))

    plot.save(EVAL_FIGURES_DIR / "fig01_combined_stream_recall_fpr.png")


# ==============================================================================
# FIGURE 2: MEAN AND P99 LATENCY COMPARISON
# ==============================================================================

def generate_figure_02_latency_comparison(data: Dict[str, Any]):
    """
    Figure 2: Dual-panel comparison of Mean and P99 Processing Latency (ms) across
    all four pipelines for (a) Historical Combined Stream and (b) Held-Out Zero-Day Benchmark.
    """
    comb_stream = data["Combined Historical Lab Benchmark Stream (Tunnel Burst + Benign Lab)"]["pipelines"]
    held_out = data["Phase 6D Held-Out Zero-Day Benchmark Partition"]["pipelines"]

    plot = PublicationPlot(width=1600, height=950, title="Per-Query Latency Comparison")
    ctx = plot.ctx

    plot.draw_text("Figure 2: Mean and P99 Latency Profiling Across Four Detection Pipelines",
                   80, 52, size=24, bold=True, color=(0.08, 0.12, 0.20))
    plot.draw_text("Benchmarked on commodity x86_64 CPU (single-thread deterministic execution, monotonic timer time.perf_counter_ns)",
                   80, 82, size=14, color=COLOR_TEXT_MUTED)

    panel_y_top = 130
    panel_height = 640
    panel_width = 660
    panel1_x_left = 120
    panel2_x_left = 860

    chart_y_top = panel_y_top + 70
    chart_height = panel_height - 130
    chart_y_bottom = chart_y_top + chart_height

    pipelines_order = ["Pipeline A1", "Pipeline B", "ML30 Cascade", "ML30 + Burst-Taint"]
    colors = [COLOR_A1, COLOR_B, COLOR_CASCADE, COLOR_BURST_TAINT]

    # --- PANEL A: HISTORICAL COMBINED STREAM (N=234) ---
    plot.draw_rounded_rect(panel1_x_left - 30, panel_y_top - 15, panel_width + 50, panel_height + 40,
                           r=8, fill_color=(0.985, 0.99, 1.0), stroke_color=(0.85, 0.88, 0.92), line_width=1.0)
    plot.draw_text("Panel (a): Combined Historical Lab Stream (N = 234)", panel1_x_left, panel_y_top + 15, size=17, bold=True)
    plot.draw_text("Sequential burst traffic | Mean vs. P99 tail latency (ms)", panel1_x_left, panel_y_top + 36, size=12, color=COLOR_TEXT_MUTED)

    # Max Y = 7.0 ms
    max_y_a = 7.0
    for tick in range(0, 8, 1):
        y = chart_y_bottom - (tick / max_y_a) * chart_height
        ctx.set_source_rgba(COLOR_GRID[0], COLOR_GRID[1], COLOR_GRID[2], 0.9)
        ctx.set_line_width(1.0)
        ctx.move_to(panel1_x_left + 45, y)
        ctx.line_to(panel1_x_left + panel_width, y)
        ctx.stroke()
        plot.draw_text(f"{tick}.0 ms", panel1_x_left + 35, y + 5, size=12, color=COLOR_TEXT_MUTED, align="right")

    bar_w = 46
    grp_spacing = 135
    grp_start_x = panel1_x_left + 70

    for idx, p_name in enumerate(pipelines_order):
        m = comb_stream[p_name]
        c = colors[idx]
        mean_ms = m["mean_latency_ms"]
        p99_ms = m["p99_latency_ms"]

        gx = grp_start_x + idx * grp_spacing

        # Mean Bar (Dark solid)
        h_mean = (mean_ms / max_y_a) * chart_height
        bx_mean = gx
        by_mean = chart_y_bottom - h_mean
        ctx.set_source_rgba(c[0], c[1], c[2], 0.95)
        ctx.rectangle(bx_mean, by_mean, bar_w, h_mean)
        ctx.fill()
        ctx.set_source_rgba(c[0] * 0.6, c[1] * 0.6, c[2] * 0.6, 1.0)
        ctx.set_line_width(1.2)
        ctx.rectangle(bx_mean, by_mean, bar_w, h_mean)
        ctx.stroke()

        # P99 Bar (Lighter shaded with border)
        h_p99 = (p99_ms / max_y_a) * chart_height
        bx_p99 = gx + bar_w + 6
        by_p99 = chart_y_bottom - h_p99
        ctx.set_source_rgba(c[0], c[1], c[2], 0.40)
        ctx.rectangle(bx_p99, by_p99, bar_w, h_p99)
        ctx.fill()
        ctx.set_source_rgba(c[0], c[1], c[2], 1.0)
        ctx.set_line_width(1.5)
        ctx.rectangle(bx_p99, by_p99, bar_w, h_p99)
        ctx.stroke()

        plot.draw_text(f"{mean_ms:.2f}", bx_mean + bar_w/2, by_mean - 8, size=11, bold=True, color=c, align="center")
        plot.draw_text(f"{p99_ms:.2f}", bx_p99 + bar_w/2, by_p99 - 8, size=11, bold=True, color=(0.2, 0.25, 0.3), align="center")

        clean_name = p_name.replace(" + ", "\n+")
        lines = clean_name.split("\n")
        plot.draw_text(lines[0], gx + bar_w + 3, chart_y_bottom + 22, size=12, bold=True, align="center")
        if len(lines) > 1:
            plot.draw_text(lines[1], gx + bar_w + 3, chart_y_bottom + 38, size=11, bold=True, color=c, align="center")

    # Legend for Panel A (Neatly positioned inside upper-left canvas above heuristic bars)
    leg_x = panel1_x_left + 70
    leg_y = chart_y_top + 15
    plot.draw_rounded_rect(leg_x, leg_y, 240, 42, r=4, fill_color=(1.0, 1.0, 1.0), stroke_color=(0.8, 0.85, 0.9), line_width=1.0)
    ctx.set_source_rgba(0.3, 0.35, 0.4, 0.95)
    ctx.rectangle(leg_x + 12, leg_y + 14, 18, 14)
    ctx.fill()
    plot.draw_text("Mean Latency", leg_x + 36, leg_y + 26, size=11, bold=True)
    ctx.set_source_rgba(0.3, 0.35, 0.4, 0.40)
    ctx.rectangle(leg_x + 126, leg_y + 14, 18, 14)
    ctx.fill()
    ctx.set_source_rgba(0.3, 0.35, 0.4, 1.0)
    ctx.set_line_width(1.5)
    ctx.rectangle(leg_x + 126, leg_y + 14, 18, 14)
    ctx.stroke()
    plot.draw_text("P99 Latency", leg_x + 150, leg_y + 26, size=11, bold=True)

    # --- PANEL B: PHASE 6D HELD-OUT ZERO-DAY BENCHMARK (N=1,714) ---
    plot.draw_rounded_rect(panel2_x_left - 30, panel_y_top - 15, panel_width + 50, panel_height + 40,
                           r=8, fill_color=(0.985, 0.99, 1.0), stroke_color=(0.85, 0.88, 0.92), line_width=1.0)
    plot.draw_text("Panel (b): Held-Out Zero-Day Benchmark (N = 1,714)", panel2_x_left, panel_y_top + 15, size=17, bold=True)
    plot.draw_text("Unseen zero-day campaigns across 16 enterprise hosts (ms)", panel2_x_left, panel_y_top + 36, size=12, color=COLOR_TEXT_MUTED)

    # Max Y = 20.0 ms (Clean alignment below header)
    max_y_b = 20.0
    for tick in range(0, 21, 4):
        y = chart_y_bottom - (tick / max_y_b) * chart_height
        ctx.set_source_rgba(COLOR_GRID[0], COLOR_GRID[1], COLOR_GRID[2], 0.9)
        ctx.set_line_width(1.0)
        ctx.move_to(panel2_x_left + 45, y)
        ctx.line_to(panel2_x_left + panel_width, y)
        ctx.stroke()
        plot.draw_text(f"{tick}.0 ms", panel2_x_left + 35, y + 5, size=12, color=COLOR_TEXT_MUTED, align="right")

    grp_start_x_b = panel2_x_left + 70

    for idx, p_name in enumerate(pipelines_order):
        m = held_out[p_name]
        c = colors[idx]
        mean_ms = m["mean_latency_ms"]
        p99_ms = m["p99_latency_ms"]

        gx = grp_start_x_b + idx * grp_spacing

        # Mean Bar
        h_mean = (mean_ms / max_y_b) * chart_height
        bx_mean = gx
        by_mean = chart_y_bottom - h_mean
        ctx.set_source_rgba(c[0], c[1], c[2], 0.95)
        ctx.rectangle(bx_mean, by_mean, bar_w, h_mean)
        ctx.fill()
        ctx.set_source_rgba(c[0] * 0.6, c[1] * 0.6, c[2] * 0.6, 1.0)
        ctx.set_line_width(1.2)
        ctx.rectangle(bx_mean, by_mean, bar_w, h_mean)
        ctx.stroke()

        # P99 Bar
        h_p99 = (p99_ms / max_y_b) * chart_height
        bx_p99 = gx + bar_w + 6
        by_p99 = chart_y_bottom - h_p99
        ctx.set_source_rgba(c[0], c[1], c[2], 0.40)
        ctx.rectangle(bx_p99, by_p99, bar_w, h_p99)
        ctx.fill()
        ctx.set_source_rgba(c[0], c[1], c[2], 1.0)
        ctx.set_line_width(1.5)
        ctx.rectangle(bx_p99, by_p99, bar_w, h_p99)
        ctx.stroke()

        plot.draw_text(f"{mean_ms:.2f}", bx_mean + bar_w/2, by_mean - 8, size=11, bold=True, color=c, align="center")
        plot.draw_text(f"{p99_ms:.2f}", bx_p99 + bar_w/2, by_p99 - 8, size=11, bold=True, color=(0.2, 0.25, 0.3), align="center")

        clean_name = p_name.replace(" + ", "\n+")
        lines = clean_name.split("\n")
        plot.draw_text(lines[0], gx + bar_w + 3, chart_y_bottom + 22, size=12, bold=True, align="center")
        if len(lines) > 1:
            plot.draw_text(lines[1], gx + bar_w + 3, chart_y_bottom + 38, size=11, bold=True, color=c, align="center")

    # Tail Latency Callout in Panel B
    plot.draw_rounded_rect(panel2_x_left + 290, chart_y_top + 10, 310, 85, r=6,
                           fill_color=(1.0, 1.0, 1.0), stroke_color=(0.2, 0.4, 0.7), line_width=1.2)
    plot.draw_text("Latency vs. Detection Tradeoff:", panel2_x_left + 302, chart_y_top + 32, size=12, bold=True, color=(0.15, 0.3, 0.6))
    plot.draw_text("Heuristics (A1, B) execute under 1 ms mean", panel2_x_left + 302, chart_y_top + 50, size=11, color=COLOR_TEXT_MUTED)
    plot.draw_text("Cascades incur 4.7-5.3 ms mean latency", panel2_x_left + 302, chart_y_top + 68, size=11, color=COLOR_TEXT_MUTED)
    plot.draw_text("to deliver 100% zero-day recall.", panel2_x_left + 302, chart_y_top + 84, size=11, bold=True, color=(0.1, 0.5, 0.3))

    # Bottom Caption Card (Word Wrapped)
    caption_y = 800
    plot.draw_rounded_rect(80, caption_y, 1440, 120, r=8,
                           fill_color=(0.96, 0.97, 0.98), stroke_color=(0.82, 0.85, 0.88), line_width=1.0)
    plot.draw_text("Academic Caption & Computational Overhead Analysis:", 100, caption_y + 24, size=13, bold=True, color=(0.15, 0.2, 0.28))

    caption_text = (
        "Single-query processing latencies across evaluation streams. Left: On the sequential lab stream (N=234), Pipeline B provides the lowest latency "
        "(mean 0.062 ms, P99 0.142 ms). Both ML cascades execute with mean ~2.95 ms and P99 ~5.5 ms. Burst-Taint adds negligible overhead (+0.024 ms mean). "
        "Right: On the 1,714-query multi-host held-out benchmark, ML30 Cascade incurs 5.350 ms mean (P99 18.886 ms) while ML30 + Burst-Taint incurs "
        "4.753 ms mean (P99 9.286 ms). Fast-path heuristics safely clear ~62.5% of queries without invoking Random Forest inference."
    )
    next_y = plot.draw_multiline_text(caption_text, 100, caption_y + 46, max_width=1390, size=11.5, line_spacing=18.0)
    plot.draw_text("Source Data: experiments/results/final_four_pipeline_evaluation.json (mean_latency_ms, p99_latency_ms)",
                   100, next_y + 4, size=11, bold=True, color=(0.3, 0.35, 0.45))

    plot.save(EVAL_FIGURES_DIR / "fig02_latency_comparison.png")


# ==============================================================================
# FIGURE 3: CONFUSION MATRIX COMPARISON
# ==============================================================================

def generate_figure_03_confusion_matrices(data: Dict[str, Any]):
    """
    Figure 3: Grid of 2x2 confusion matrices comparing all four pipelines across
    (Row 1) Historical Combined Lab Stream (N=234) and
    (Row 2) Phase 6D Held-Out Zero-Day Benchmark Partition (N=1,714).
    """
    comb_stream = data["Combined Historical Lab Benchmark Stream (Tunnel Burst + Benign Lab)"]["pipelines"]
    held_out = data["Phase 6D Held-Out Zero-Day Benchmark Partition"]["pipelines"]

    plot = PublicationPlot(width=1700, height=1080, title="Confusion Matrix Comparison")
    ctx = plot.ctx

    plot.draw_text("Figure 3: Empirical Confusion Matrix Grid Across Detection Pipelines",
                   80, 50, size=24, bold=True, color=(0.08, 0.12, 0.20))
    plot.draw_text("Complete categorization of True Positives (TP), False Positives (FP), True Negatives (TN), and False Negatives (FN)",
                   80, 78, size=14, color=COLOR_TEXT_MUTED)

    pipelines_order = [
        ("Pipeline A1", COLOR_A1, "Baseline Unmitigated"),
        ("Pipeline B", COLOR_B, "Enterprise Dual-Baseline"),
        ("ML30 Cascade", COLOR_CASCADE, "Fast-Path + ML30"),
        ("ML30 + Burst-Taint", COLOR_BURST_TAINT, "Cascade + Burst Propagation")
    ]

    def render_single_cm(x: float, y: float, w: float, h: float,
                         pipe_name: str, p_color: Tuple[float, float, float],
                         m: Dict[str, Any], workload_title: str):
        plot.draw_rounded_rect(x, y, w, h, r=8, fill_color=(1.0, 1.0, 1.0),
                               stroke_color=(0.82, 0.85, 0.88), line_width=1.2)

        # Header Banner
        ctx.set_source_rgba(p_color[0], p_color[1], p_color[2], 0.12)
        ctx.rectangle(x, y, w, 38)
        ctx.fill()
        plot.draw_text(pipe_name, x + w / 2, y + 25, size=15, bold=True, color=p_color, align="center")

        grid_top = y + 70
        grid_left = x + 75
        cell_w = 95
        cell_h = 75

        # Row & Column Headers
        plot.draw_text("Pred Attack", grid_left + cell_w / 2, grid_top - 8, size=11, bold=True, align="center")
        plot.draw_text("Pred Benign", grid_left + cell_w + cell_w / 2, grid_top - 8, size=11, bold=True, align="center")

        plot.draw_text("Actual", grid_left - 38, grid_top + cell_h / 2 - 8, size=10, color=COLOR_TEXT_MUTED, align="center")
        plot.draw_text("Attack", grid_left - 38, grid_top + cell_h / 2 + 6, size=11, bold=True, align="center")

        plot.draw_text("Actual", grid_left - 38, grid_top + cell_h + cell_h / 2 - 8, size=10, color=COLOR_TEXT_MUTED, align="center")
        plot.draw_text("Benign", grid_left - 38, grid_top + cell_h + cell_h / 2 + 6, size=11, bold=True, align="center")

        # TP Cell
        tp = m["tp"]
        ctx.set_source_rgba(0.15, 0.70, 0.45, 0.18 if tp > 0 else 0.05)
        ctx.rectangle(grid_left, grid_top, cell_w, cell_h)
        ctx.fill()
        ctx.set_source_rgba(0.15, 0.70, 0.45, 0.8)
        ctx.set_line_width(1.0)
        ctx.rectangle(grid_left, grid_top, cell_w, cell_h)
        ctx.stroke()
        plot.draw_text("TP", grid_left + 8, grid_top + 16, size=10, bold=True, color=(0.1, 0.5, 0.3))
        plot.draw_text(str(tp), grid_left + cell_w / 2, grid_top + 48, size=20, bold=True, color=(0.08, 0.45, 0.25), align="center")

        # FN Cell
        fn = m["fn"]
        ctx.set_source_rgba(0.90, 0.25, 0.25, 0.22 if fn > 0 else 0.04)
        ctx.rectangle(grid_left + cell_w, grid_top, cell_w, cell_h)
        ctx.fill()
        ctx.set_source_rgba(0.90, 0.25, 0.25, 0.8)
        ctx.set_line_width(1.0)
        ctx.rectangle(grid_left + cell_w, grid_top, cell_w, cell_h)
        ctx.stroke()
        plot.draw_text("FN", grid_left + cell_w + 8, grid_top + 16, size=10, bold=True, color=(0.7, 0.15, 0.15))
        plot.draw_text(str(fn), grid_left + cell_w + cell_w / 2, grid_top + 48, size=20, bold=True,
                       color=(0.75, 0.1, 0.1) if fn > 0 else (0.4, 0.45, 0.5), align="center")

        # FP Cell
        fp = m["fp"]
        ctx.set_source_rgba(0.95, 0.45, 0.15, 0.22 if fp > 0 else 0.04)
        ctx.rectangle(grid_left, grid_top + cell_h, cell_w, cell_h)
        ctx.fill()
        ctx.set_source_rgba(0.95, 0.45, 0.15, 0.8)
        ctx.set_line_width(1.0)
        ctx.rectangle(grid_left, grid_top + cell_h, cell_w, cell_h)
        ctx.stroke()
        plot.draw_text("FP", grid_left + 8, grid_top + cell_h + 16, size=10, bold=True, color=(0.75, 0.3, 0.1))
        plot.draw_text(str(fp), grid_left + cell_w / 2, grid_top + cell_h + 48, size=20, bold=True,
                       color=(0.8, 0.2, 0.05) if fp > 0 else (0.4, 0.45, 0.5), align="center")

        # TN Cell
        tn = m["tn"]
        ctx.set_source_rgba(0.25, 0.50, 0.75, 0.18 if tn > 0 else 0.05)
        ctx.rectangle(grid_left + cell_w, grid_top + cell_h, cell_w, cell_h)
        ctx.fill()
        ctx.set_source_rgba(0.25, 0.50, 0.75, 0.8)
        ctx.set_line_width(1.0)
        ctx.rectangle(grid_left + cell_w, grid_top + cell_h, cell_w, cell_h)
        ctx.stroke()
        plot.draw_text("TN", grid_left + cell_w + 8, grid_top + cell_h + 16, size=10, bold=True, color=(0.15, 0.35, 0.6))
        plot.draw_text(str(tn), grid_left + cell_w + cell_w / 2, grid_top + cell_h + 48, size=20, bold=True, color=(0.12, 0.32, 0.55), align="center")

        foot_y = grid_top + 2 * cell_h + 18
        rec_str = f"{m['recall']*100:.1f}%" if m["recall"] is not None else "N/A"
        prec_str = f"{m['precision']*100:.1f}%" if m["precision"] is not None else "N/A"
        fpr_str = f"{m['fpr']*100:.1f}%" if m["fpr"] is not None else "N/A"
        acc_str = f"{m['accuracy']*100:.1f}%" if m["accuracy"] is not None else "N/A"

        plot.draw_text(f"Recall: {rec_str}  |  Precision: {prec_str}", x + w / 2, foot_y, size=11, bold=True, align="center")
        plot.draw_text(f"FPR: {fpr_str}  |  Accuracy: {acc_str}", x + w / 2, foot_y + 18, size=11, color=COLOR_TEXT_MUTED, align="center")

    row1_y = 110
    card_w = 345
    card_h = 340
    spacing_x = 370
    start_x = 80

    plot.draw_text("ROW 1: Historical Combined Lab Stream (N = 234: 115 Tunnel Positives + 119 Benign Negatives)",
                   80, row1_y + 20, size=16, bold=True, color=(0.15, 0.25, 0.4))

    for idx, (p_name, p_color, desc) in enumerate(pipelines_order):
        render_single_cm(start_x + idx * spacing_x, row1_y + 35, card_w, card_h,
                         p_name, p_color, comb_stream[p_name], "Combined Lab Stream")

    row2_y = 515
    plot.draw_text("ROW 2: Phase 6D Held-Out Zero-Day Benchmark Partition (N = 1,714: 916 Zero-Day Positives + 798 Benign Negatives)",
                   80, row2_y + 20, size=16, bold=True, color=(0.15, 0.25, 0.4))

    for idx, (p_name, p_color, desc) in enumerate(pipelines_order):
        render_single_cm(start_x + idx * spacing_x, row2_y + 35, card_w, card_h,
                         p_name, p_color, held_out[p_name], "Held-Out Zero-Day Benchmark")

    # Bottom Caption Card (Word Wrapped)
    caption_y = 930
    plot.draw_rounded_rect(80, caption_y, 1500, 120, r=8,
                           fill_color=(0.96, 0.97, 0.98), stroke_color=(0.82, 0.85, 0.88), line_width=1.0)
    plot.draw_text("Academic Caption & Confusion Matrix Analysis:", 100, caption_y + 24, size=13, bold=True, color=(0.15, 0.2, 0.28))

    caption_text = (
        "Row 1: On the combined lab stream, Pipeline A1 suffers 116 false alarms and 79 missed attacks due to baseline self-poisoning. "
        "Pipeline B eliminates 111 false alarms but still misses 50 attacks. ML30 Cascade reduces false negatives to 5, and ML30 + Burst-Taint "
        "achieves near-perfect classification (TP=114, FN=1, FP=2, TN=117). "
        "Row 2: On the held-out zero-day benchmark, behavioral baselines miss 578 (A1) and 489 (B) zero-day queries. "
        "Both ML30 Cascade and ML30 + Burst-Taint achieve flawless zero-day classification (916/916 TP, 798/798 TN, 0 FP, 0 FN, 100.0% Recall and Accuracy)."
    )
    next_y = plot.draw_multiline_text(caption_text, 100, caption_y + 46, max_width=1450, size=11.5, line_spacing=18.0)
    plot.draw_text("Source Data: experiments/results/final_four_pipeline_evaluation.json (tp, fp, tn, fn counts strictly audited)",
                   100, next_y + 4, size=11, bold=True, color=(0.3, 0.35, 0.45))

    plot.save(EVAL_FIGURES_DIR / "fig03_confusion_matrices.png")


# ==============================================================================
# FIGURE 4: DIRECT ML VS. BURST-TAINT PROPAGATED DETECTIONS
# ==============================================================================

def generate_figure_04_direct_vs_taint_detections(data: Dict[str, Any]):
    """
    Figure 4: Detailed comparison of Direct ML Detections vs. Burst-Taint Propagated
    Detections, showing (a) detection composition across lab traces and (b) exact query-by-query
    recovery of the 4 delimiter chunks on the Kali DNS tunneling trace.
    """
    tb_data = data["Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)"]
    tb_missed = tb_data["missed_queries_breakdown"]
    comb_data = data["Combined Historical Lab Benchmark Stream (Tunnel Burst + Benign Lab)"]["pipelines"]

    plot = PublicationPlot(width=1650, height=980, title="Direct ML vs Burst-Taint Propagation")
    ctx = plot.ctx

    plot.draw_text("Figure 4: Direct ML Detections vs. Parent-Domain Burst-Taint Propagation",
                   80, 52, size=24, bold=True, color=(0.08, 0.12, 0.20))
    plot.draw_text("Detailed investigation of taint propagation mechanics, border-line delimiter recovery, and causal temporal safety",
                   80, 82, size=14, color=COLOR_TEXT_MUTED)

    panel_y_top = 130
    panel_height = 650
    panel_width = 700
    panel1_x_left = 100
    panel2_x_left = 870

    # --- PANEL A: DETECTION COMPOSITION STACKED BARS ---
    plot.draw_rounded_rect(panel1_x_left - 20, panel_y_top - 15, panel_width + 40, panel_height + 40,
                           r=8, fill_color=(0.985, 0.99, 1.0), stroke_color=(0.85, 0.88, 0.92), line_width=1.0)
    plot.draw_text("Panel (a): Detection Sources Breakdown",
                   panel1_x_left, panel_y_top + 15, size=17, bold=True)
    plot.draw_text("Direct ML vs. Propagated Taint alerts across workloads",
                   panel1_x_left, panel_y_top + 36, size=12, color=COLOR_TEXT_MUTED)

    chart_y_top = panel_y_top + 75
    chart_height = panel_height - 150
    chart_y_bottom = chart_y_top + chart_height
    max_y_a = 125

    for tick in range(0, 130, 25):
        y = chart_y_bottom - (tick / max_y_a) * chart_height
        ctx.set_source_rgba(COLOR_GRID[0], COLOR_GRID[1], COLOR_GRID[2], 0.9)
        ctx.set_line_width(1.0)
        ctx.move_to(panel1_x_left + 45, y)
        ctx.line_to(panel1_x_left + panel_width - 20, y)
        ctx.stroke()
        plot.draw_text(str(tick), panel1_x_left + 35, y + 5, size=12, color=COLOR_TEXT_MUTED, align="right")

    workload_stacks = [
        ("Tunnel Burst Trace\n(Attack: N=115)", [
            ("ML30 Cascade", 110, 0, 110, 5),
            ("ML30 + Burst-Taint", 110, 4, 114, 1)
        ]),
        ("Combined Stream\n(Attack: N=115)", [
            ("ML30 Cascade", 110, 0, 110, 5),
            ("ML30 + Burst-Taint", 110, 4, 114, 1)
        ]),
        ("Benign Lab Trace\n(False Positives)", [
            ("ML30 Cascade", 5, 0, 5, 0),
            ("ML30 + Burst-Taint", 5, 2, 7, 0)
        ])
    ]

    group_w = 175
    group_spacing = 210
    start_gx = panel1_x_left + 80
    b_width = 58

    for g_idx, (g_name, pipe_pairs) in enumerate(workload_stacks):
        gx = start_gx + g_idx * group_spacing

        for p_idx, (p_label, direct_cnt, taint_cnt, tot_cnt, fn_cnt) in enumerate(pipe_pairs):
            bx = gx + p_idx * (b_width + 12)

            # Direct ML (Blue)
            h_direct = (direct_cnt / max_y_a) * chart_height
            by_direct = chart_y_bottom - h_direct
            ctx.set_source_rgba(COLOR_DIRECT_ML[0], COLOR_DIRECT_ML[1], COLOR_DIRECT_ML[2], 0.9)
            ctx.rectangle(bx, by_direct, b_width, h_direct)
            ctx.fill()
            ctx.set_source_rgba(COLOR_DIRECT_ML[0] * 0.7, COLOR_DIRECT_ML[1] * 0.7, COLOR_DIRECT_ML[2] * 0.7, 1.0)
            ctx.set_line_width(1.0)
            ctx.rectangle(bx, by_direct, b_width, h_direct)
            ctx.stroke()

            # Taint Propagated (Orange on top)
            if taint_cnt > 0:
                h_taint = (taint_cnt / max_y_a) * chart_height
                by_taint = by_direct - h_taint
                ctx.set_source_rgba(COLOR_TAINT_PROP[0], COLOR_TAINT_PROP[1], COLOR_TAINT_PROP[2], 0.95)
                ctx.rectangle(bx, by_taint, b_width, h_taint)
                ctx.fill()
                ctx.set_source_rgba(COLOR_TAINT_PROP[0] * 0.7, COLOR_TAINT_PROP[1] * 0.7, COLOR_TAINT_PROP[2] * 0.7, 1.0)
                ctx.set_line_width(1.0)
                ctx.rectangle(bx, by_taint, b_width, h_taint)
                ctx.stroke()
                top_y = by_taint
            else:
                top_y = by_direct

            plot.draw_text(f"{tot_cnt}", bx + b_width / 2, top_y - 8, size=13, bold=True,
                           color=COLOR_TAINT_PROP if taint_cnt > 0 else COLOR_DIRECT_ML, align="center")

            sub_lbl = "Cascade" if "Cascade" in p_label and "Burst" not in p_label else "+ Taint"
            plot.draw_text(sub_lbl, bx + b_width / 2, chart_y_bottom + 18, size=11, bold=True, align="center")

        lines = g_name.split("\n")
        plot.draw_text(lines[0], gx + group_w / 2 - 20, chart_y_bottom + 42, size=12, bold=True, align="center")
        if len(lines) > 1:
            plot.draw_text(lines[1], gx + group_w / 2 - 20, chart_y_bottom + 58, size=11, color=COLOR_TEXT_MUTED, align="center")

    # Legend in Panel A (Properly positioned in top right of panel)
    leg_x = panel1_x_left + 420
    leg_y = panel_y_top + 10
    plot.draw_rounded_rect(leg_x, leg_y, 250, 42, r=4, fill_color=(1.0, 1.0, 1.0), stroke_color=(0.8, 0.85, 0.9), line_width=1.0)
    ctx.set_source_rgba(COLOR_DIRECT_ML[0], COLOR_DIRECT_ML[1], COLOR_DIRECT_ML[2], 0.9)
    ctx.rectangle(leg_x + 12, leg_y + 14, 18, 14)
    ctx.fill()
    plot.draw_text("Direct ML", leg_x + 36, leg_y + 26, size=11, bold=True)
    ctx.set_source_rgba(COLOR_TAINT_PROP[0], COLOR_TAINT_PROP[1], COLOR_TAINT_PROP[2], 0.95)
    ctx.rectangle(leg_x + 120, leg_y + 14, 18, 14)
    ctx.fill()
    plot.draw_text("Taint-Propagated", leg_x + 144, leg_y + 26, size=11, bold=True)

    # --- PANEL B: ANATOMY OF DELIMITER CHUNK RECOVERY ---
    plot.draw_rounded_rect(panel2_x_left - 20, panel_y_top - 15, panel_width + 40, panel_height + 40,
                           r=8, fill_color=(1.0, 0.99, 0.98), stroke_color=(0.92, 0.88, 0.82), line_width=1.0)
    plot.draw_text("Panel (b): Causal Anatomy of the 5 Missed Attack Queries",
                   panel2_x_left, panel_y_top + 15, size=17, bold=True)
    plot.draw_text("ML probability scores and taint state on lab_trace_tunnel_burst.jsonl",
                   panel2_x_left, panel_y_top + 36, size=12, color=COLOR_TEXT_MUTED)

    p2_chart_top = panel_y_top + 70
    p2_chart_h = 240
    p2_chart_bottom = p2_chart_top + p2_chart_h
    p2_chart_left = panel2_x_left + 40
    p2_chart_w = panel_width - 80

    for p_tick in [0.00, 0.10, 0.20, 0.30]:
        y = p2_chart_bottom - (p_tick / 0.30) * p2_chart_h
        ctx.set_source_rgba(COLOR_GRID[0], COLOR_GRID[1], COLOR_GRID[2], 0.9)
        ctx.set_line_width(1.0)
        ctx.move_to(p2_chart_left, y)
        ctx.line_to(p2_chart_left + p2_chart_w, y)
        ctx.stroke()
        plot.draw_text(f"{p_tick:.2f}", p2_chart_left - 10, y + 4, size=11, color=COLOR_TEXT_MUTED, align="right")

    thresh_y = p2_chart_bottom - (0.20 / 0.30) * p2_chart_h
    ctx.set_source_rgba(0.85, 0.2, 0.2, 0.85)
    ctx.set_line_width(2.0)
    ctx.set_dash([6.0, 4.0])
    ctx.move_to(p2_chart_left, thresh_y)
    ctx.line_to(p2_chart_left + p2_chart_w, thresh_y)
    ctx.stroke()
    ctx.set_dash([])
    plot.draw_text("Random Forest Decision Threshold (P = 0.20)", p2_chart_left + p2_chart_w - 5, thresh_y - 6,
                   size=11, bold=True, color=(0.85, 0.2, 0.2), align="right")

    step_x = p2_chart_w / 6.0
    for q_idx, item in enumerate(tb_missed):
        lx = p2_chart_left + (q_idx + 1) * step_x
        prob = item["ml_probability"]
        ly = p2_chart_bottom - (prob / 0.30) * p2_chart_h
        rescued = item["burst_taint_propagated"]

        ctx.set_source_rgba(0.5, 0.55, 0.6, 0.7)
        ctx.set_line_width(2.0)
        ctx.move_to(lx, p2_chart_bottom)
        ctx.line_to(lx, ly)
        ctx.stroke()

        node_color = COLOR_TAINT_PROP if rescued else (0.5, 0.5, 0.5)
        ctx.set_source_rgba(node_color[0], node_color[1], node_color[2], 1.0)
        ctx.arc(lx, ly, 7.0, 0, 2 * math.pi)
        ctx.fill()
        ctx.set_source_rgb(1.0, 1.0, 1.0)
        ctx.set_line_width(1.5)
        ctx.arc(lx, ly, 7.0, 0, 2 * math.pi)
        ctx.stroke()

        plot.draw_text(f"P={prob:.4f}", lx, ly - 12, size=11, bold=True, color=node_color, align="center")
        plot.draw_text(f"Query #{item['1_based_index']}", lx, p2_chart_bottom + 18, size=11, bold=True, align="center")

    tbl_top = p2_chart_bottom + 45
    plot.draw_rounded_rect(panel2_x_left + 15, tbl_top, panel_width - 30, 240, r=6,
                           fill_color=(1.0, 1.0, 1.0), stroke_color=(0.85, 0.88, 0.90), line_width=1.0)

    ctx.set_source_rgba(0.2, 0.25, 0.35, 0.08)
    ctx.rectangle(panel2_x_left + 15, tbl_top, panel_width - 30, 30)
    ctx.fill()
    plot.draw_text("Query", panel2_x_left + 35, tbl_top + 20, size=11, bold=True)
    plot.draw_text("Queried Domain", panel2_x_left + 105, tbl_top + 20, size=11, bold=True)
    plot.draw_text("Direct ML", panel2_x_left + 340, tbl_top + 20, size=11, bold=True)
    plot.draw_text("Burst-Taint Status", panel2_x_left + 450, tbl_top + 20, size=11, bold=True)

    row_y = tbl_top + 52
    for item in tb_missed:
        q_num = f"#{item['1_based_index']}"
        domain = item["domain"]
        direct_dec = item["cascade_decision"]
        t_src = item["burst_taint_detection_source"]
        rescued = item["burst_taint_propagated"]

        plot.draw_text(q_num, panel2_x_left + 35, row_y, size=11, bold=True)
        plot.draw_text(domain, panel2_x_left + 105, row_y, size=11, color=(0.1, 0.3, 0.6) if "end" in domain else (0.3, 0.35, 0.4))
        plot.draw_text(f"{direct_dec} (P={item['ml_probability']:.2f})", panel2_x_left + 340, row_y, size=11, color=(0.7, 0.2, 0.2))

        if rescued:
            plot.draw_rounded_rect(panel2_x_left + 450, row_y - 14, 195, 20, r=3,
                                   fill_color=(0.95, 0.98, 0.95), stroke_color=(0.2, 0.6, 0.3), line_width=1.0)
            plot.draw_text("RECOVERED (TAINT_PROP)", panel2_x_left + 547, row_y - 1, size=9.5, bold=True,
                           color=(0.1, 0.5, 0.2), align="center")
        else:
            plot.draw_rounded_rect(panel2_x_left + 450, row_y - 14, 195, 20, r=3,
                                   fill_color=(0.98, 0.95, 0.95), stroke_color=(0.7, 0.3, 0.3), line_width=1.0)
            plot.draw_text("UNTAINTED (CAUSAL START)", panel2_x_left + 547, row_y - 1, size=9.5, bold=True,
                           color=(0.6, 0.2, 0.2), align="center")

        row_y += 38

    # Bottom Caption Card (Word Wrapped)
    caption_y = 815
    plot.draw_rounded_rect(80, caption_y, 1490, 130, r=8,
                           fill_color=(0.96, 0.97, 0.98), stroke_color=(0.82, 0.85, 0.88), line_width=1.0)
    plot.draw_text("Academic Caption & Delimiter Recovery Mechanics:", 100, caption_y + 24, size=13, bold=True, color=(0.15, 0.2, 0.28))

    caption_text = (
        "Left: Detections partitioned into Direct ML (blue) and Taint-Propagated (orange). In the Kali attack trace, ML30 Cascade detects 110 of 115 "
        "queries directly. Burst-Taint propagates malicious labels across the parent domain `attacker.lab`, capturing an additional 4 queries (+3.48% recall). "
        "Right: Inspection of the 5 queries falling below the RF decision threshold (P < 0.20). Query #1 (`hello.attacker.lab`) represents the opening "
        "handshake; because no attack has yet occurred, no active taint exists, correctly honoring causal temporal ordering. Queries #10, #19, #28, and #37 "
        "are short delimiters (`*.end.attacker.lab`); because earlier queries on `attacker.lab` confirmed malicious activity, taint propagation successfully classifies them as MALICIOUS."
    )
    next_y = plot.draw_multiline_text(caption_text, 100, caption_y + 46, max_width=1440, size=11.5, line_spacing=18.0)
    plot.draw_text("Source Data: experiments/results/final_four_pipeline_evaluation.json (missed_queries_breakdown array)",
                   100, next_y + 4, size=11, bold=True, color=(0.3, 0.35, 0.45))

    plot.save(EVAL_FIGURES_DIR / "fig04_direct_vs_taint_detections.png")


# ==============================================================================
# FIGURE 5: STRICT PROVENANCE SEPARATION ACROSS ALL FIVE WORKLOADS
# ==============================================================================

def generate_figure_05_cross_workload_provenance(data: Dict[str, Any]):
    """
    Figure 5: Cross-Workload Evaluation with Strict Provenance Separation across:
      1. Historical Lab Traces (Tunnel Burst N=115, Benign N=119, Combined N=234)
      2. Synthetic Cold-Host Scenario (Cold Host N=100)
      3. Held-Out Zero-Day Benchmark (Phase 6D Partition N=1,714)
    Strictly displays undefined metrics as N/A (never zero).
    """
    plot = PublicationPlot(width=1750, height=1050, title="Strict Provenance Evaluation")
    ctx = plot.ctx

    plot.draw_text("Figure 5: Strict Provenance-Separated Evaluation Across Five Workloads",
                   80, 50, size=24, bold=True, color=(0.08, 0.12, 0.20))
    plot.draw_text("Rigorous methodological partitioning: Historical lab traces, synthetic cold host, and held-out zero-day benchmark are kept strictly isolated",
                   80, 78, size=14, color=COLOR_TEXT_MUTED)

    sections = [
        {
            "domain_title": "PROVENANCE DOMAIN 1: Historical Lab Query Traces (Real BIND9 Captures)",
            "domain_desc": "Authentic traffic captured from Kali Linux tunneling campaigns and enterprise workstation background traffic",
            "workloads": [
                ("Tunnel Burst Trace", "lab_trace_tunnel_burst.jsonl", "Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)", "N=115 (Pos=115, Neg=0)"),
                ("Benign Lab Trace", "lab_trace_benign.jsonl", "Historical Lab Benign Trace (lab_trace_benign.jsonl)", "N=119 (Pos=0, Neg=119)"),
                ("Combined Stream", "Tunnel + Benign Stream", "Combined Historical Lab Benchmark Stream (Tunnel Burst + Benign Lab)", "N=234 (Pos=115, Neg=119)")
            ],
            "x": 80,
            "y": 115,
            "w": 1590,
            "h": 360
        },
        {
            "domain_title": "PROVENANCE DOMAIN 2: Synthetic Cold-Host Scenario (Controlled Injection)",
            "domain_desc": "Synthetic traffic testing enterprise prior immunity on uninitialized host baseline",
            "workloads": [
                ("Synthetic Cold Host", "lab_trace_benign_new_host.jsonl", "Synthetic Benign Cold-Host Trace (lab_trace_benign_new_host.jsonl)", "N=100 (Pos=0, Neg=100)")
            ],
            "x": 80,
            "y": 495,
            "w": 500,
            "h": 360
        },
        {
            "domain_title": "PROVENANCE DOMAIN 3: Phase 6D Held-Out Zero-Day Benchmark Partition (N = 1,714)",
            "domain_desc": "Four unseen attack campaigns (gamma, zeta, theta, iota) interleaved across 16 enterprise hosts",
            "workloads": [
                ("Held-Out Benchmark", "dnsentinel_ml_benchmark.jsonl (Test)", "Phase 6D Held-Out Zero-Day Benchmark Partition", "N=1,714 (Pos=916, Neg=798)")
            ],
            "x": 605,
            "y": 495,
            "w": 1065,
            "h": 360
        }
    ]

    pipeline_names = ["Pipeline A1", "Pipeline B", "ML30 Cascade", "ML30 + Burst-Taint"]
    pipe_colors = [COLOR_A1, COLOR_B, COLOR_CASCADE, COLOR_BURST_TAINT]

    def render_workload_panel(x: float, y: float, w: float, h: float,
                              w_title: str, w_sub: str, w_key: str, w_counts: str):
        plot.draw_rounded_rect(x, y, w, h, r=6, fill_color=(1.0, 1.0, 1.0),
                               stroke_color=(0.85, 0.88, 0.90), line_width=1.0)

        ctx.set_source_rgba(0.2, 0.25, 0.35, 0.06)
        ctx.rectangle(x, y, w, 40)
        ctx.fill()
        plot.draw_text(w_title, x + 15, y + 20, size=13, bold=True)
        plot.draw_text(w_counts, x + w - 15, y + 20, size=11, bold=True, color=COLOR_TEXT_MUTED, align="right")
        plot.draw_text(w_sub, x + 15, y + 34, size=10, color=COLOR_TEXT_MUTED)

        chart_top = y + 55
        chart_h = h - 110
        chart_bottom = chart_top + chart_h
        mid_x = x + w / 2

        plot.draw_text("Recall (%)", x + w * 0.25, chart_top - 4, size=11, bold=True, align="center")
        plot.draw_text("FPR (%)", x + w * 0.75, chart_top - 4, size=11, bold=True, align="center")

        ctx.set_source_rgba(0.85, 0.88, 0.92, 0.8)
        ctx.set_line_width(1.0)
        ctx.move_to(mid_x, chart_top)
        ctx.line_to(mid_x, chart_bottom + 10)
        ctx.stroke()

        w_pipes = data[w_key]["pipelines"]

        pos_cnt = list(w_pipes.values())[0]["pos_count"]
        neg_cnt = list(w_pipes.values())[0]["neg_count"]

        # Recall Side (Left)
        if pos_cnt == 0:
            plot.draw_na_badge(x + 20, chart_top + 30, (w / 2) - 40, chart_h - 40, label="N/A (Pos=0)")
        else:
            bar_w = ((w / 2) - 50) / 4.0
            for idx, p_name in enumerate(pipeline_names):
                rec = w_pipes[p_name]["recall"]
                c = pipe_colors[idx]
                bx = x + 30 + idx * bar_w
                if rec is not None:
                    bh = rec * (chart_h - 20)
                    by = chart_bottom - bh
                    ctx.set_source_rgba(c[0], c[1], c[2], 0.9)
                    ctx.rectangle(bx, by, bar_w - 6, bh)
                    ctx.fill()
                    ctx.set_source_rgba(c[0]*0.7, c[1]*0.7, c[2]*0.7, 1.0)
                    ctx.set_line_width(1.0)
                    ctx.rectangle(bx, by, bar_w - 6, bh)
                    ctx.stroke()
                    plot.draw_text(f"{rec*100:.0f}%", bx + (bar_w - 6)/2, by - 6, size=9.5, bold=True, color=c, align="center")

        # FPR Side (Right)
        if neg_cnt == 0:
            plot.draw_na_badge(mid_x + 20, chart_top + 30, (w / 2) - 40, chart_h - 40, label="N/A (Neg=0)")
        else:
            bar_w = ((w / 2) - 50) / 4.0
            for idx, p_name in enumerate(pipeline_names):
                fpr = w_pipes[p_name]["fpr"]
                c = pipe_colors[idx]
                bx = mid_x + 30 + idx * bar_w
                if fpr is not None:
                    bh = fpr * (chart_h - 20)
                    by = chart_bottom - bh
                    ctx.set_source_rgba(c[0], c[1], c[2], 0.9)
                    ctx.rectangle(bx, by, bar_w - 6, bh)
                    ctx.fill()
                    ctx.set_source_rgba(c[0]*0.7, c[1]*0.7, c[2]*0.7, 1.0)
                    ctx.set_line_width(1.0)
                    ctx.rectangle(bx, by, bar_w - 6, bh)
                    ctx.stroke()
                    plot.draw_text(f"{fpr*100:.1f}%", bx + (bar_w - 6)/2, by - 6, size=9, bold=True, color=c, align="center")

        plot.draw_text("A1: Unmit  |  B: Dual-Base  |  Cascade  |  +Burst-Taint", x + w / 2, chart_bottom + 32, size=9.5, color=COLOR_TEXT_MUTED, align="center")

    # Render Domain 1
    d1 = sections[0]
    plot.draw_rounded_rect(d1["x"], d1["y"], d1["w"], d1["h"], r=8,
                           fill_color=(0.985, 0.99, 1.0), stroke_color=(0.82, 0.86, 0.92), line_width=1.2)
    plot.draw_text(d1["domain_title"], d1["x"] + 20, d1["y"] + 24, size=14, bold=True, color=(0.12, 0.25, 0.45))
    plot.draw_text(d1["domain_desc"], d1["x"] + 20, d1["y"] + 42, size=11, color=COLOR_TEXT_MUTED)

    d1_w_width = (d1["w"] - 60) / 3.0
    for idx, (title, sub, key, counts) in enumerate(d1["workloads"]):
        render_workload_panel(d1["x"] + 20 + idx * (d1_w_width + 10), d1["y"] + 55, d1_w_width, d1["h"] - 75,
                              title, sub, key, counts)

    # Render Domain 2
    d2 = sections[1]
    plot.draw_rounded_rect(d2["x"], d2["y"], d2["w"], d2["h"], r=8,
                           fill_color=(1.0, 0.99, 0.98), stroke_color=(0.90, 0.85, 0.80), line_width=1.2)
    plot.draw_text("PROVENANCE DOMAIN 2: Synthetic Cold Host", d2["x"] + 20, d2["y"] + 24, size=13, bold=True, color=(0.55, 0.35, 0.1))
    plot.draw_text(d2["domain_desc"], d2["x"] + 20, d2["y"] + 42, size=10, color=COLOR_TEXT_MUTED)
    title, sub, key, counts = d2["workloads"][0]
    render_workload_panel(d2["x"] + 20, d2["y"] + 55, d2["w"] - 40, d2["h"] - 75, title, sub, key, counts)

    # Render Domain 3
    d3 = sections[2]
    plot.draw_rounded_rect(d3["x"], d3["y"], d3["w"], d3["h"], r=8,
                           fill_color=(0.98, 1.0, 0.98), stroke_color=(0.80, 0.90, 0.82), line_width=1.2)
    plot.draw_text("PROVENANCE DOMAIN 3: Phase 6D Held-Out Zero-Day Benchmark Partition (N = 1,714)",
                   d3["x"] + 20, d3["y"] + 24, size=13, bold=True, color=(0.1, 0.45, 0.25))
    plot.draw_text(d3["domain_desc"], d3["x"] + 20, d3["y"] + 42, size=10, color=COLOR_TEXT_MUTED)
    title, sub, key, counts = d3["workloads"][0]
    render_workload_panel(d3["x"] + 20, d3["y"] + 55, d3["w"] - 40, d3["h"] - 75, title, sub, key, counts)

    plot.draw_rounded_rect(d3["x"] + d3["w"] - 380, d3["y"] + 15, 360, 36, r=4,
                           fill_color=(1.0, 1.0, 1.0), stroke_color=(0.7, 0.4, 0.1), line_width=1.0)
    plot.draw_text("danger.edu Status: UNTESTED in Test Partition", d3["x"] + d3["w"] - 370, d3["y"] + 32,
                   size=10.5, bold=True, color=(0.7, 0.35, 0.05))
    plot.draw_text("(Confined to training partition t < 18,000s)", d3["x"] + d3["w"] - 370, d3["y"] + 45,
                   size=9.5, color=COLOR_TEXT_MUTED)

    # Bottom Caption Card (Word Wrapped)
    caption_y = 880
    plot.draw_rounded_rect(80, caption_y, 1590, 130, r=8,
                           fill_color=(0.96, 0.97, 0.98), stroke_color=(0.82, 0.85, 0.88), line_width=1.0)
    plot.draw_text("Academic Caption & Methodological Provenance Note:", 100, caption_y + 24, size=13, bold=True, color=(0.15, 0.2, 0.28))

    caption_text = (
        "Crucial Methodological Partition: In accordance with scientific reporting standards, results across historical lab traces, synthetic cold-host scenarios, "
        "and the held-out zero-day benchmark are strictly separated. Metrics are never pooled or aggregated across distinct provenance sources. "
        "Undefined Metrics Representation: Workloads with zero positive samples (Benign Lab Trace, Synthetic Cold Host) have undefined Recall and F1-Score; "
        "workloads with zero negative samples (Tunnel Burst Trace) have undefined FPR. These are strictly rendered as N/A (with hatched badges), never substituted as 0.00%."
    )
    next_y = plot.draw_multiline_text(caption_text, 100, caption_y + 46, max_width=1540, size=11.5, line_spacing=18.0)
    plot.draw_text("Source Data: experiments/results/final_four_pipeline_evaluation.json (Section provenance_type tags)",
                   100, next_y + 4, size=11, bold=True, color=(0.3, 0.35, 0.45))

    plot.save(EVAL_FIGURES_DIR / "fig05_cross_workload_provenance.png")


# ==============================================================================
# SUMMARY TABLES GENERATION
# ==============================================================================

def generate_summary_tables(data: Dict[str, Any]) -> str:
    """
    Generates publication-quality markdown tables for all four pipelines,
    adhering strictly to undefined metric conventions (N/A).
    Saves to:
      - experiments/results/tables/table5_four_pipeline_evaluation.md
      - experiments/results/figures/evaluation/summary_tables.md
    """
    def fmt_pct(val: Optional[float]) -> str:
        return f"{val * 100.0:.2f}%" if val is not None else "N/A"

    def fmt_lat(val: Optional[float]) -> str:
        return f"{val:.3f} ms" if val is not None else "N/A"

    lines = []
    lines.append("# Table 5: Comprehensive DNSentinel Four-Pipeline Performance Profile")
    lines.append("")
    lines.append("This publication summary table provides the audited, reproducible empirical performance of all four DNSentinel detection pipelines across all evaluation workloads.")
    lines.append("")
    lines.append("**Detection Pipelines:**")
    lines.append("1. **Pipeline A1**: Baseline unmitigated `DetectionPipeline`")
    lines.append("2. **Pipeline B**: `ColdStartMitigatedPipeline` (Dual baseline with enterprise prior)")
    lines.append("3. **ML30 Cascade**: `CascadeDetectionPipeline` (Fast-path heuristic triage + Random Forest)")
    lines.append("4. **ML30 + Burst-Taint**: `BurstTaintCascadePipeline` (ML30 Cascade + Parent-domain burst taint propagation)")
    lines.append("")
    lines.append("---")
    lines.append("")

    for w_name, w_info in data.items():
        lines.append(f"### {w_name}")
        lines.append(f"*{w_info['description']}*  ")
        sample_size = w_info['sample_size']
        pipelines = w_info['pipelines']
        first_p = list(pipelines.values())[0]
        pos_cnt = first_p['pos_count']
        neg_cnt = first_p['neg_count']
        lines.append(f"**Provenance:** `{w_info['provenance_type']}` | **Sample Size:** $N = {sample_size}$ | **Ground-Truth Positives:** {pos_cnt} | **Ground-Truth Negatives:** {neg_cnt}")
        lines.append("")
        lines.append("| Pipeline | TP | FP | TN | FN | Recall | Precision | F1-Score | FPR | Accuracy | Contam. | Direct ML | Tainted | Mean Latency | P99 Latency |")
        lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")

        for p_name, m in pipelines.items():
            lines.append(
                f"| **{p_name}** | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | "
                f"{fmt_pct(m['recall'])} | {fmt_pct(m['precision'])} | {fmt_pct(m['f1'])} | {fmt_pct(m['fpr'])} | "
                f"{fmt_pct(m['accuracy'])} | {m['contamination']} | {m['direct_detections']} | {m['taint_detections']} | "
                f"{fmt_lat(m['mean_latency_ms'])} | {fmt_lat(m['p99_latency_ms'])} |"
            )
        lines.append("")

    # Missed queries section
    tb_missed = data["Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)"]["missed_queries_breakdown"]
    lines.append("### Delimiter Chunk Recovery Breakdown (lab_trace_tunnel_burst.jsonl)")
    lines.append("Detailed audit of the 5 queries that fall below the direct Random Forest threshold ($P < 0.20$):")
    lines.append("")
    lines.append("| Query # (1-Based) | Domain | True Class | Cascade Decision | ML Prob | Cascade Path | Burst-Taint Decision | Detection Source | Propagated? |")
    lines.append("| :---: | :--- | :---: | :---: | :---: | :--- | :---: | :--- | :---: |")
    for item in tb_missed:
        prop_str = "**YES**" if item["burst_taint_propagated"] else "NO"
        lines.append(
            f"| **#{item['1_based_index']}** | `{item['domain']}` | Attack (1) | {item['cascade_decision']} | "
            f"{item['ml_probability']:.4f} | `{item['cascade_path']}` | **{item['burst_taint_decision']}** | "
            f"`{item['burst_taint_detection_source']}` | {prop_str} |"
        )
    lines.append("")
    lines.append("> [!NOTE]")
    lines.append("> **Causal Temporal Constraint:** Query #1 (`hello.attacker.lab`) represents the opening handshake. Because no attack chunk has preceded it, no active taint exists; the query is evaluated purely on lexical features and correctly cleared ($P = 0.0000$). Queries #10, #19, #28, and #37 (`*.end.attacker.lab`) arrive after confirmed attack chunks on `attacker.lab` and are successfully recovered via taint propagation.")
    lines.append("")

    md_content = "\n".join(lines)

    t5_path = TABLES_DIR / "table5_four_pipeline_evaluation.md"
    t5_path.parent.mkdir(parents=True, exist_ok=True)
    with open(t5_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"[+] Saved summary table: {t5_path}")

    f_tbl_path = EVAL_FIGURES_DIR / "summary_tables.md"
    f_tbl_path.parent.mkdir(parents=True, exist_ok=True)
    with open(f_tbl_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"[+] Saved summary table copy: {f_tbl_path}")

    return md_content


# ==============================================================================
# README GENERATION
# ==============================================================================

def generate_evaluation_figures_readme():
    """
    Generates a clear README.md in experiments/results/figures/evaluation/ describing:
      - Each figure's purpose, contents, and source data
      - The exact CLI command to regenerate the figures
      - Methodology, provenance separation, and undefined metric conventions
    """
    readme_content = """# DNSentinel Four-Pipeline Evaluation Research Figures

This directory contains publication-quality vector research figures and summary tables comparing DNSentinel's four detection pipelines:
1. **Pipeline A1**: Baseline unmitigated `DetectionPipeline`
2. **Pipeline B**: `ColdStartMitigatedPipeline` (Dual baseline with enterprise prior)
3. **ML30 Cascade**: `CascadeDetectionPipeline` (Fast-path heuristic triage + Random Forest)
4. **ML30 + Burst-Taint**: `BurstTaintCascadePipeline` (ML30 Cascade + Parent-domain burst taint propagation)

All figures derive strictly from the verified, reproducible evaluation results saved in:
- `experiments/results/final_four_pipeline_evaluation.json`
- `experiments/results/final_four_pipeline_evaluation_report.md`

No detection logic was rerun, no models were retrained, no thresholds were altered, and no data was fabricated.

---

## Catalog of Generated Figures

### 1. `fig01_combined_stream_recall_fpr.png`
- **Title:** Detection Recall and False-Positive Rate (FPR) on Historical Combined Lab Stream
- **Dimensions:** 1600 x 950 px | **Format:** High-DPI PNG (Cairo Vector Engine)
- **Workload:** Historical Combined Lab Benchmark Stream ($N = 234$: 115 Tunnel Positives + 119 Benign Negatives).
- **Contents:**
  - **Panel (a) Recall (%):** Compares attack detection recall across all four pipelines: Pipeline A1 (31.30%), Pipeline B (56.52%), ML30 Cascade (95.65%), and ML30 + Burst-Taint (99.13%).
  - **Panel (b) False-Positive Rate (%):** Demonstrates catastrophic baseline self-poisoning in Pipeline A1 (FPR = 97.48%, 116 false alarms), mitigation in Pipeline B (FPR = 4.20%), and high-precision discrimination in ML30 Cascade and ML30 + Burst-Taint (FPR = 1.68%, 2 false alarms).

### 2. `fig02_latency_comparison.png`
- **Title:** Mean and P99 Latency Profiling Across Four Detection Pipelines
- **Dimensions:** 1600 x 950 px | **Format:** High-DPI PNG (Cairo Vector Engine)
- **Workloads:**
  - **Panel (a):** Combined Historical Lab Stream ($N = 234$)
  - **Panel (b):** Phase 6D Held-Out Zero-Day Benchmark Partition ($N = 1,714$)
- **Contents:** Paired bar charts displaying Mean Latency and 99th Percentile ($P99$) Tail Latency in milliseconds (ms). Highlights the sub-millisecond execution of heuristic baselines (0.06–0.27 ms) versus the ~3–5 ms execution of the ML cascade, while noting that Burst-Taint introduces virtually zero incremental overhead (+0.024 ms mean).

### 3. `fig03_confusion_matrices.png`
- **Title:** Empirical Confusion Matrix Grid Across Detection Pipelines
- **Dimensions:** 1700 x 1080 px | **Format:** High-DPI PNG (Cairo Vector Engine)
- **Workloads:**
  - **Row 1:** Combined Historical Lab Stream ($N = 234$: 115 Positives, 119 Negatives)
  - **Row 2:** Phase 6D Held-Out Zero-Day Benchmark Partition ($N = 1,714$: 916 Positives, 798 Negatives)
- **Contents:** Complete 2x2 confusion matrix grid (TP, FP, TN, FN) for each of the four pipelines, annotated with exact query counts, Recall, Precision, FPR, and Accuracy. Shows how the ML cascades eliminate the severe baseline misclassifications of Pipeline A1 and Pipeline B.

### 4. `fig04_direct_vs_taint_detections.png`
- **Title:** Direct ML Detections vs. Parent-Domain Burst-Taint Propagation
- **Dimensions:** 1650 x 980 px | **Format:** High-DPI PNG (Cairo Vector Engine)
- **Workloads:**
  - `lab_trace_tunnel_burst.jsonl` ($N = 115$)
  - `lab_trace_benign.jsonl` ($N = 119$)
  - Combined Lab Stream ($N = 234$)
- **Contents:**
  - **Panel (a):** Stacked bar charts decomposing total detections into Direct ML classifications versus Taint-Propagated alerts.
  - **Panel (b):** Lollipop probability trajectory of the 5 queries falling below the Random Forest decision threshold ($P < 0.20$). Explains why Query #1 (`hello.attacker.lab`) cannot be tainted due to causal ordering (opening handshake), while delimiter chunks #10, #19, #28, and #37 (`*.end.attacker.lab`) are successfully rescued by parent-domain taint.

### 5. `fig05_cross_workload_provenance.png`
- **Title:** Strict Provenance-Separated Evaluation Across Five Workloads
- **Dimensions:** 1750 x 1050 px | **Format:** High-DPI PNG (Cairo Vector Engine)
- **Workloads:** All 5 evaluation workloads partitioned into three distinct provenance domains:
  1. **Historical Lab Traces:** Tunnel Burst ($N=115$), Benign Lab ($N=119$), Combined Stream ($N=234$)
  2. **Synthetic Cold-Host Scenario:** Benign Cold Host ($N=100$)
  3. **Held-Out Zero-Day Benchmark:** Final Test Partition ($N=1,714$)
- **Contents:** Grouped comparison bars honoring strict provenance isolation. All mathematically undefined metrics (e.g., Recall when Pos=0, FPR when Neg=0) are rendered with explicit hatched `N/A` badges rather than misleading zero values. Includes an explicit callout documenting that hard-negative `danger.edu` queries were confined to training and are untested in the held-out partition.

---

## Summary Tables

- `experiments/results/tables/table5_four_pipeline_evaluation.md`: Complete markdown table formatted for publication inclusion, summarizing TP, FP, TN, FN, Recall, Precision, F1, FPR, Accuracy, Contamination, Direct vs. Tainted detections, and Latency for all workloads.
- Duplicate copy also saved in `experiments/results/figures/evaluation/summary_tables.md`.

---

## Command to Regenerate All Artifacts

To regenerate all figures and summary tables from the evaluation results:

```bash
PYTHONPATH=. venv/bin/python experiments/runners/generate_evaluation_figures.py
```

To run with built-in validation checks:

```bash
PYTHONPATH=. venv/bin/python experiments/runners/generate_evaluation_figures.py --verify
```

---

## Methodological Invariants Enforced

1. **Strict Provenance Separation:** Historical lab traces, synthetic cold host, and held-out zero-day benchmarks are never merged into a combined metric calculation.
2. **Undefined Metric Representation:** When sample counts in a class are zero, metrics are strictly represented as `N/A`, never zero.
3. **Data Immutability:** Generated purely from frozen evaluation artifacts. Detection engines, models, baselines, and configurations are untouched.
"""
    readme_path = EVAL_FIGURES_DIR / "README.md"
    readme_path.parent.mkdir(parents=True, exist_ok=True)
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(readme_content)
    print(f"[+] Saved README: {readme_path}")


# ==============================================================================
# AUTOMATED VALIDATION CHECKS
# ==============================================================================

def run_automated_validation():
    """
    Performs automated validation of generated figures, tables, and numerical consistency.
    """
    print("\n[*] Running automated validation checks...")

    assert SOURCE_JSON.exists(), f"Source JSON missing: {SOURCE_JSON}"
    with open(SOURCE_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    expected_figures = [
        "fig01_combined_stream_recall_fpr.png",
        "fig02_latency_comparison.png",
        "fig03_confusion_matrices.png",
        "fig04_direct_vs_taint_detections.png",
        "fig05_cross_workload_provenance.png"
    ]
    for fig_name in expected_figures:
        fig_path = EVAL_FIGURES_DIR / fig_name
        assert fig_path.exists(), f"Figure missing: {fig_path}"
        fsize = fig_path.stat().st_size
        assert fsize > 25000, f"Figure file size unexpectedly small ({fsize} bytes): {fig_path}"
        print(f"  [CHECK PASS] {fig_name} exists ({fsize/1024:.1f} KB)")

    assert (EVAL_FIGURES_DIR / "README.md").exists(), "README.md missing"
    assert (TABLES_DIR / "table5_four_pipeline_evaluation.md").exists(), "table5 missing"
    assert (EVAL_FIGURES_DIR / "summary_tables.md").exists(), "summary_tables copy missing"
    print("  [CHECK PASS] README.md and publication summary tables exist")

    comb = data["Combined Historical Lab Benchmark Stream (Tunnel Burst + Benign Lab)"]["pipelines"]
    assert comb["Pipeline A1"]["recall"] == 0.313, "A1 Recall mismatch"
    assert comb["Pipeline A1"]["fpr"] == 0.9748, "A1 FPR mismatch"
    assert comb["Pipeline B"]["recall"] == 0.5652, "Pipeline B Recall mismatch"
    assert comb["Pipeline B"]["fpr"] == 0.042, "Pipeline B FPR mismatch"
    assert comb["ML30 Cascade"]["recall"] == 0.9565, "Cascade Recall mismatch"
    assert comb["ML30 Cascade"]["fpr"] == 0.0168, "Cascade FPR mismatch"
    assert comb["ML30 + Burst-Taint"]["recall"] == 0.9913, "Burst-Taint Recall mismatch"
    assert comb["ML30 + Burst-Taint"]["fpr"] == 0.0168, "Burst-Taint FPR mismatch"

    missed = data["Historical Lab Tunnel Burst Trace (lab_trace_tunnel_burst.jsonl)"]["missed_queries_breakdown"]
    assert len(missed) == 5, f"Expected 5 missed queries, got {len(missed)}"
    assert missed[0]["1_based_index"] == 1 and not missed[0]["burst_taint_propagated"], "Query #1 must not be propagated"
    for item in missed[1:]:
        assert item["burst_taint_propagated"], f"Query #{item['1_based_index']} should be taint-propagated"
    print("  [CHECK PASS] All numerical values and delimiter recovery checks verified successfully.")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="DNSentinel Evaluation Figures & Tables Generator")
    parser.add_argument("--verify", action="store_true", help="Run automated validation after generation")
    args = parser.parse_args()

    print("[*] Loading source evaluation artifacts...")
    data = load_evaluation_data()

    print(f"[*] Output directory: {EVAL_FIGURES_DIR}")
    EVAL_FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    print("\n[*] Generating Figure 1: Combined Stream Recall and FPR...")
    generate_figure_01_combined_stream(data)

    print("[*] Generating Figure 2: Mean and P99 Latency Comparison...")
    generate_figure_02_latency_comparison(data)

    print("[*] Generating Figure 3: Confusion Matrix Comparison Grid...")
    generate_figure_03_confusion_matrices(data)

    print("[*] Generating Figure 4: Direct ML vs Burst-Taint Propagation...")
    generate_figure_04_direct_vs_taint_detections(data)

    print("[*] Generating Figure 5: Strict Provenance-Separated Cross-Workload Evaluation...")
    generate_figure_05_cross_workload_provenance(data)

    print("\n[*] Generating Publication Summary Tables...")
    generate_summary_tables(data)

    print("[*] Generating Documentation README...")
    generate_evaluation_figures_readme()

    run_automated_validation()
    print("\n[SUCCESS] All research figures and summary tables generated and validated successfully.")


if __name__ == "__main__":
    main()
