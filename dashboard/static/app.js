/**
 * DNSentinel SOC Dashboard — Reactive Frontend Controller
 * Uses HTTP polling (1s interval) with zero external JavaScript dependencies.
 */

(function () {
  'use strict';

  // State Management
  const state = {
    isPolling: true,
    pollingIntervalMs: 1000,
    pollTimer: null,
    statusTimer: null,
    activeTab: 'tab-live',
    selectedHost: null,
    riskFilter: 'ALL',
    alertSeverityFilter: 'ALL',
    isDemoReplay: false,
    selectedEvent: null,
    allLiveEvents: [],
    allAlerts: []
  };

  // DOM Elements
  const elements = {
    replayBanner: document.getElementById('replay-banner'),
    replayBannerText: document.getElementById('replay-banner-text'),
    bindStatus: document.getElementById('bind-status'),
    captureStatus: document.getElementById('capture-status'),
    hostsCount: document.getElementById('hosts-count'),
    btnPausePoll: document.getElementById('btn-pause-poll'),
    pollIcon: document.getElementById('poll-icon'),
    pollLabel: document.getElementById('poll-label'),
    btnClearFeed: document.getElementById('btn-clear-feed'),
    btnReplayBenign: document.getElementById('btn-replay-benign'),
    btnReplayBenignMature: document.getElementById('btn-replay-benign-mature'),
    btnReplayTunnel: document.getElementById('btn-replay-tunnel'),
    btnReplayTunnelB: document.getElementById('btn-replay-tunnel-b'),
    btnReplayTunnelCascade: document.getElementById('btn-replay-tunnel-cascade'),
    btnTestCustom: document.getElementById('btn-test-custom'),
    customDomainInput: document.getElementById('custom-domain-input'),
    btnExportAlerts: document.getElementById('btn-export-alerts'),
    filterRisk: document.getElementById('filter-risk'),
    filterAlertSeverity: document.getElementById('filter-alert-severity'),

    // Metric Summary Counters
    statTotal: document.getElementById('stat-total'),
    statNormal: document.getElementById('stat-normal'),
    statNormalPct: document.getElementById('stat-normal-pct'),
    statLow: document.getElementById('stat-low'),
    statLowPct: document.getElementById('stat-low-pct'),
    statSuspicious: document.getElementById('stat-suspicious'),
    statHigh: document.getElementById('stat-high'),
    statLastTime: document.getElementById('stat-last-time'),
    badgeAlertsCount: document.getElementById('badge-alerts-count'),

    // Section 1: Tables & Buffers
    tbodyLive: document.getElementById('tbody-live-events'),
    liveEmptyState: document.getElementById('live-empty-state'),
    liveBufferInfo: document.getElementById('live-buffer-info'),

    // Section 2: Risk Overview
    barNormal: document.getElementById('bar-normal'),
    barLow: document.getElementById('bar-low'),
    barSuspicious: document.getElementById('bar-suspicious'),
    barHigh: document.getElementById('bar-high'),
    statCardNormal: document.getElementById('stat-card-normal'),
    statCardLow: document.getElementById('stat-card-low'),
    statCardSuspicious: document.getElementById('stat-card-suspicious'),
    statCardHigh: document.getElementById('stat-card-high'),
    riskAlertCount: document.getElementById('risk-alert-count'),

    // Section 3: Behavioral Analysis
    behaviorSelectedLabel: document.getElementById('behavior-selected-label'),
    behaviorMetaHost: document.getElementById('behavior-meta-host'),
    behaviorMetaDomain: document.getElementById('behavior-meta-domain'),
    behaviorMetaScore: document.getElementById('behavior-meta-score'),
    behaviorMetaConf: document.getElementById('behavior-meta-conf'),
    tierBarEntropy: document.getElementById('tier-bar-entropy'),
    tierBarLength: document.getElementById('tier-bar-length'),
    tierBarRate: document.getElementById('tier-bar-rate'),
    tierBarNovel: document.getElementById('tier-bar-novel'),
    tierBarOrg: document.getElementById('tier-bar-org'),
    tierValEntropy: document.getElementById('tier-val-entropy'),
    tierValLength: document.getElementById('tier-val-length'),
    tierValRate: document.getElementById('tier-val-rate'),
    tierValNovel: document.getElementById('tier-val-novel'),
    tierValOrg: document.getElementById('tier-val-org'),
    swRateVal: document.getElementById('sw-rate-val'),
    swBurstStatus: document.getElementById('sw-burst-status'),

    // Section 4: Host Views
    selectHostProfile: document.getElementById('select-host-profile'),
    hostDetailsView: document.getElementById('host-details-view'),
    hostEmptyState: document.getElementById('host-empty-state'),
    hostDisplayIp: document.getElementById('host-display-ip'),
    hostCalibrationState: document.getElementById('host-calibration-state'),
    hostTotalQ: document.getElementById('host-total-q'),
    hostAvgEntropy: document.getElementById('host-avg-entropy'),
    hostAvgLength: document.getElementById('host-avg-length'),
    hostUniqueDomains: document.getElementById('host-unique-domains'),
    tbodyHostDomains: document.getElementById('tbody-host-domains'),
    hostQueryTypes: document.getElementById('host-query-types'),
    hostsCardsGrid: document.getElementById('hosts-cards-grid'),

    // Section 5: Alert View
    tbodyAlerts: document.getElementById('tbody-alerts'),
    alertsEmptyState: document.getElementById('alerts-empty-state'),

    // Section 6: Research Tab
    tbodyTunnelEye: document.getElementById('tbody-tunneleye-research'),
    tbodyAblation: document.getElementById('tbody-ablation-research'),
    tbodyColdStart: document.getElementById('tbody-coldstart-research'),
    imageModal: document.getElementById('image-modal'),
    modalImage: document.getElementById('modal-image'),
    modalCaption: document.getElementById('modal-caption'),
    modalClose: document.getElementById('modal-close'),

    // Section 7: System Tab
    sysBindVal: document.getElementById('sys-bind-val'),
    sysIfaceVal: document.getElementById('sys-iface-val'),
    sysHostsVal: document.getElementById('sys-hosts-val'),
    sysOrgVal: document.getElementById('sys-org-val'),
    sysBufVal: document.getElementById('sys-buf-val'),
    sysModelsVal: document.getElementById('sys-models-val')
  };

  // ========================================================================
  // Initialization
  // ========================================================================

  function init() {
    setupTabNavigation();
    setupEventListeners();
    setupImageModal();
    fetchSystemStatus();
    fetchSummary();
    fetchLiveEvents();
    fetchAlerts();
    loadHostList();
    loadResearchResults();

    startPolling();
  }

  // ========================================================================
  // Tab Navigation (7 Independent Sections)
  // ========================================================================

  function setupTabNavigation() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-tab');
        if (!targetId) return;

        tabButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        document.querySelectorAll('.tab-content').forEach(section => {
          section.classList.remove('active');
        });

        const activeSection = document.getElementById(targetId);
        if (activeSection) {
          activeSection.classList.add('active');
          state.activeTab = targetId;

          // Trigger view-specific loads
          if (targetId === 'tab-hosts') {
            loadHostList();
          } else if (targetId === 'tab-research') {
            loadResearchResults();
          } else if (targetId === 'tab-system') {
            fetchSystemStatus();
          } else if (targetId === 'tab-behavior') {
            if (state.selectedEvent) {
              updateBehavioralGauges(state.selectedEvent);
            } else if (state.allLiveEvents.length > 0) {
              updateBehavioralGauges(state.allLiveEvents[0]);
            }
          }
        }
      });
    });
  }

  // ========================================================================
  // Event Listeners
  // ========================================================================

  function setupEventListeners() {
    // Pause / Resume Polling
    if (elements.btnPausePoll) {
      elements.btnPausePoll.addEventListener('click', togglePolling);
    }

    // Clear Feed
    if (elements.btnClearFeed) {
      elements.btnClearFeed.addEventListener('click', clearFeed);
    }

    // Replay Benign (Unmitigated Cold Start)
    if (elements.btnReplayBenign) {
      elements.btnReplayBenign.addEventListener('click', () => {
        triggerReplay('benign');
      });
    }

    // Replay Benign (Mature Organization)
    if (elements.btnReplayBenignMature) {
      elements.btnReplayBenignMature.addEventListener('click', () => {
        triggerReplay('benign_mature');
      });
    }

    // Replay Tunnel Burst (Pipeline A1 - Unmitigated Cold Start)
    if (elements.btnReplayTunnel) {
      elements.btnReplayTunnel.addEventListener('click', () => {
        triggerReplay('tunnel');
      });
    }

    // Replay Tunnel Burst (Pipeline B - Heuristic Enterprise Prior)
    if (elements.btnReplayTunnelB) {
      elements.btnReplayTunnelB.addEventListener('click', () => {
        triggerReplay('tunnel_b');
      });
    }

    // Replay Tunnel Burst (ML30 Cascade - Tiered Detection)
    if (elements.btnReplayTunnelCascade) {
      elements.btnReplayTunnelCascade.addEventListener('click', () => {
        triggerReplay('tunnel_cascade');
      });
    }

    // Test Custom Domain
    if (elements.btnTestCustom) {
      elements.btnTestCustom.addEventListener('click', submitCustomTest);
    }
    if (elements.customDomainInput) {
      elements.customDomainInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') submitCustomTest();
      });
    }

    // Host Selector
    if (elements.selectHostProfile) {
      elements.selectHostProfile.addEventListener('change', (e) => {
        const host = e.target.value;
        if (host) {
          state.selectedHost = host;
          loadHostProfile(host);
        }
      });
    }

    // Risk Filter
    if (elements.filterRisk) {
      elements.filterRisk.addEventListener('change', (e) => {
        state.riskFilter = e.target.value;
        renderLiveEventsTable(state.allLiveEvents);
      });
    }

    // Alert Severity Filter
    if (elements.filterAlertSeverity) {
      elements.filterAlertSeverity.addEventListener('change', (e) => {
        state.alertSeverityFilter = e.target.value;
        renderAlertsTable(state.allAlerts);
      });
    }

    // Export Alerts
    if (elements.btnExportAlerts) {
      elements.btnExportAlerts.addEventListener('click', exportAlertsCSV);
    }
  }

  // ========================================================================
  // Figure Zoom Modal Overlay
  // ========================================================================

  function setupImageModal() {
    // Attach click handlers to figure cards
    const cards = document.querySelectorAll('.figure-card');
    cards.forEach(card => {
      card.addEventListener('click', () => {
        const imgSrc = card.getAttribute('data-img');
        const caption = card.getAttribute('data-caption') || '';
        if (imgSrc && elements.imageModal && elements.modalImage) {
          elements.modalImage.src = imgSrc;
          elements.modalCaption.textContent = caption;
          elements.imageModal.classList.remove('hidden');
        }
      });
    });

    // Close button
    if (elements.modalClose) {
      elements.modalClose.addEventListener('click', closeModal);
    }

    // Click outside modal content
    if (elements.imageModal) {
      elements.imageModal.addEventListener('click', (e) => {
        if (e.target === elements.imageModal) {
          closeModal();
        }
      });
    }

    // Close on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && elements.imageModal && !elements.imageModal.classList.contains('hidden')) {
        closeModal();
      }
    });
  }

  function closeModal() {
    if (elements.imageModal) {
      elements.imageModal.classList.add('hidden');
      if (elements.modalImage) elements.modalImage.src = '';
    }
  }

  // ========================================================================
  // HTTP Polling Engine (Every 1000ms)
  // ========================================================================

  function startPolling() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(pollCycle, state.pollingIntervalMs);

    if (state.statusTimer) clearInterval(state.statusTimer);
    state.statusTimer = setInterval(fetchSystemStatus, 3000);
  }

  function stopPolling() {
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
    if (state.statusTimer) {
      clearInterval(state.statusTimer);
      state.statusTimer = null;
    }
  }

  function togglePolling() {
    state.isPolling = !state.isPolling;
    if (state.isPolling) {
      startPolling();
      if (elements.pollIcon) elements.pollIcon.textContent = '⏸';
      if (elements.pollLabel) elements.pollLabel.textContent = 'Pause Feed';
      if (elements.btnPausePoll) {
        elements.btnPausePoll.classList.remove('btn-danger');
        elements.btnPausePoll.classList.add('btn-secondary');
      }
    } else {
      stopPolling();
      if (elements.pollIcon) elements.pollIcon.textContent = '▶';
      if (elements.pollLabel) elements.pollLabel.textContent = 'Resume Feed';
      if (elements.btnPausePoll) {
        elements.btnPausePoll.classList.remove('btn-secondary');
        elements.btnPausePoll.classList.add('btn-danger');
      }
    }
  }

  function pollCycle() {
    fetchSummary();
    fetchLiveEvents();
    fetchAlerts();
  }

  // ========================================================================
  // API Fetch Functions
  // ========================================================================

  function fetchSummary() {
    fetch('/api/summary')
      .then(r => r.json())
      .then(data => {
        elements.statTotal.textContent = data.total_queries.toLocaleString();
        elements.statNormal.textContent = data.normal_count.toLocaleString();
        elements.statLow.textContent = data.low_risk_count.toLocaleString();
        elements.statSuspicious.textContent = data.suspicious_count.toLocaleString();
        elements.statHigh.textContent = data.high_risk_count.toLocaleString();
        if (elements.hostsCount) elements.hostsCount.textContent = data.monitored_hosts_count;

        // Percentages
        const total = data.total_queries || 1;
        const normPct = ((data.normal_count / total) * 100).toFixed(1);
        const lowPct = ((data.low_risk_count / total) * 100).toFixed(1);
        const suspPct = ((data.suspicious_count / total) * 100).toFixed(1);
        const highPct = ((data.high_risk_count / total) * 100).toFixed(1);

        elements.statNormalPct.textContent = `${normPct}% of total`;
        elements.statLowPct.textContent = `${lowPct}% of total`;

        // Section 2: Risk Overview Cards & Progress Bar
        if (elements.statCardNormal) elements.statCardNormal.textContent = `Count: ${data.normal_count} (${normPct}%)`;
        if (elements.statCardLow) elements.statCardLow.textContent = `Count: ${data.low_risk_count} (${lowPct}%)`;
        if (elements.statCardSuspicious) elements.statCardSuspicious.textContent = `Count: ${data.suspicious_count} (${suspPct}%)`;
        if (elements.statCardHigh) elements.statCardHigh.textContent = `Count: ${data.high_risk_count} (${highPct}%)`;
        if (elements.riskAlertCount) elements.riskAlertCount.textContent = `${data.suspicious_count + data.high_risk_count}`;

        if (data.total_queries > 0) {
          elements.barNormal.style.width = `${normPct}%`;
          elements.barLow.style.width = `${lowPct}%`;
          elements.barSuspicious.style.width = `${suspPct}%`;
          elements.barHigh.style.width = `${highPct}%`;
        } else {
          elements.barNormal.style.width = '25%';
          elements.barLow.style.width = '25%';
          elements.barSuspicious.style.width = '25%';
          elements.barHigh.style.width = '25%';
        }

        // Demo Replay Banner
        state.isDemoReplay = data.is_demo_replay;
        if (state.isDemoReplay) {
          elements.replayBanner.classList.remove('hidden');
          if (elements.replayBannerText && data.replay_mode) {
            elements.replayBannerText.textContent = data.replay_mode;
          }
        } else {
          elements.replayBanner.classList.add('hidden');
        }

        if (data.last_query_timestamp) {
          elements.statLastTime.textContent = `Last: ${formatTimeOnly(data.last_query_timestamp)}`;
        }
        if (elements.liveBufferInfo) {
          elements.liveBufferInfo.textContent = `${data.buffer_size} queries buffered`;
        }
        if (elements.sysBufVal) {
          elements.sysBufVal.textContent = `${data.buffer_size} / 300`;
        }
      })
      .catch(() => {});
  }

  function fetchLiveEvents() {
    fetch('/api/live?limit=60')
      .then(r => r.json())
      .then(events => {
        state.allLiveEvents = events;
        renderLiveEventsTable(events);

        // If nothing manually selected, track latest event
        if (!state.selectedEvent && events.length > 0) {
          updateBehavioralGauges(events[0]);
        }
      })
      .catch(() => {});
  }

  function fetchAlerts() {
    fetch('/api/alerts?limit=50')
      .then(r => r.json())
      .then(alerts => {
        state.allAlerts = alerts;
        if (elements.badgeAlertsCount) {
          elements.badgeAlertsCount.textContent = alerts.length;
        }
        renderAlertsTable(alerts);
      })
      .catch(() => {});
  }

  function fetchSystemStatus() {
    fetch('/api/status')
      .then(r => r.json())
      .then(sys => {
        if (elements.bindStatus) {
          elements.bindStatus.textContent = sys.bind_service_active ? 'Active' : 'Standby';
        }
        if (elements.sysBindVal) {
          elements.sysBindVal.textContent = sys.bind_service_active ? 'Active (Running)' : 'Standby / Log Mode';
          elements.sysBindVal.className = sys.bind_service_active ? 'sys-value text-success' : 'sys-value text-warning';
        }

        if (elements.captureStatus) {
          elements.captureStatus.textContent = sys.interface_ready ? 'ens33 (Ready)' : 'ens33 (Offline)';
        }
        if (elements.sysIfaceVal) {
          elements.sysIfaceVal.textContent = sys.interface_ready ? 'ens33 (Operational)' : 'ens33 (Not Ready)';
        }

        if (elements.sysHostsVal) elements.sysHostsVal.textContent = sys.monitored_hosts_count;
        if (elements.sysOrgVal) {
          elements.sysOrgVal.textContent = sys.organization_initialized ? 'Initialized (Mature)' : 'Empty / Calibrating';
          elements.sysOrgVal.className = sys.organization_initialized ? 'sys-value text-success' : 'sys-value text-warning';
        }
        if (elements.sysModelsVal) {
          elements.sysModelsVal.textContent = sys.models_available ? 'Available (ML30, ML31, Calibration)' : 'Checking artifacts...';
          elements.sysModelsVal.className = sys.models_available ? 'sys-value text-success' : 'sys-value text-warning';
        }
      })
      .catch(() => {});
  }

  // ========================================================================
  // Section 1: Live Monitor Rendering
  // ========================================================================

  function formatBaselineStatus(ev) {
    const status = ev.baseline_status || (
      ev.baseline_updated ? 'Learned' :
      (ev.quarantined || ev.calibration_quarantined) ? 'Quarantined' :
      (ev.provisional_held || ev.lifecycle_state === 'COLD_START_CALIBRATION') ? 'Calibrating' :
      'Not Updated'
    );

    switch (status) {
      case 'Learned':
        return '<span class="text-success font-mono" title="Committed: Baseline profile updated">Learned</span>';
      case 'Calibrating':
        return '<span class="text-warning font-mono" title="Provisional: Buffered awaiting calibration">Calibrating</span>';
      case 'Quarantined':
        return '<span class="text-danger font-mono" title="Guarded: Host explicitly quarantined">Quarantined</span>';
      case 'Not Updated':
      default:
        return '<span class="text-muted font-mono" title="Guarded: Baseline not updated">Not Updated</span>';
    }
  }

  function formatDetectionMethod(item) {
    if (!item) {
      return '<span class="text-muted font-mono">Heuristic only</span>';
    }

    const hasPath = item.cascade_path !== null && item.cascade_path !== undefined && String(item.cascade_path).trim() !== '';
    const hasDecision = item.cascade_decision !== null && item.cascade_decision !== undefined && String(item.cascade_decision).trim() !== '';

    if (!hasPath && !hasDecision) {
      return '<span class="text-muted font-mono">Heuristic only</span>';
    }

    let probStr = 'N/A';
    if (typeof item.ml_probability === 'number' && Number.isFinite(item.ml_probability)) {
      const num = item.ml_probability;
      const pct = num <= 1.0 && num >= 0.0 ? num * 100 : num;
      probStr = `${pct.toFixed(1)}%`;
    }

    const pathHtml = hasPath ? `<span class="badge badge-primary font-mono">${escapeHtml(item.cascade_path)}</span>` : '';

    let decisionHtml = '';
    if (hasDecision) {
      const dec = String(item.cascade_decision).toUpperCase();
      const badgeClass = dec === 'MALICIOUS' ? 'badge-high' : (dec === 'BENIGN' ? 'badge-normal' : 'badge-secondary');
      decisionHtml = `<span class="badge ${badgeClass} font-mono">${escapeHtml(item.cascade_decision)}</span>`;
    }

    const probHtml = `<span class="font-mono text-muted" title="ML Probability">ML: ${escapeHtml(probStr)}</span>`;

    return `<div class="detection-method-cell">`
      + (pathHtml ? pathHtml + ' ' : '')
      + (decisionHtml ? decisionHtml + ' ' : '')
      + probHtml
      + `</div>`;
  }

  function renderLiveEventsTable(events) {
    let filtered = events;
    if (state.riskFilter !== 'ALL') {
      if (state.riskFilter === 'HIGH_RISK') {
        filtered = events.filter(e => e.risk_level === 'HIGH_RISK');
      } else if (state.riskFilter === 'SUSPICIOUS') {
        filtered = events.filter(e => e.risk_level === 'SUSPICIOUS' || e.risk_level === 'HIGH_RISK');
      } else if (state.riskFilter === 'NORMAL') {
        filtered = events.filter(e => e.risk_level === 'NORMAL');
      }
    }

    if (filtered.length === 0) {
      elements.tbodyLive.innerHTML = '';
      elements.liveEmptyState.classList.remove('hidden');
      return;
    }

    elements.liveEmptyState.classList.add('hidden');
    let rowsHtml = '';

    filtered.forEach((ev, idx) => {
      const riskClass = getRiskBadgeClass(ev.risk_level);
      const baselineAction = formatBaselineStatus(ev);
      const detectionMethodHtml = formatDetectionMethod(ev);

      rowsHtml += `
        <tr class="event-row" data-id="${ev.id}" style="cursor: pointer;">
          <td class="font-mono">${formatTimestamp(ev.timestamp)}</td>
          <td class="font-mono"><strong>${escapeHtml(ev.host)}</strong></td>
          <td class="font-mono" title="${escapeHtml(ev.domain)}">${escapeHtml(truncate(ev.domain, 45))}</td>
          <td class="font-mono">${escapeHtml(ev.query_type_name)}</td>
          <td class="font-mono">${formatNumber(ev.entropy, 4, '0.0000')}</td>
          <td class="font-mono">${ev.domain_length != null && Number.isFinite(Number(ev.domain_length)) ? Number(ev.domain_length) : 0}</td>
          <td class="font-mono">${formatNumber(ev.query_rate, 2, '0.00')}</td>
          <td class="font-mono"><strong>${formatNumber(ev.behavior_score, 1, '0.0')}</strong></td>
          <td>${detectionMethodHtml}</td>
          <td><span class="badge ${riskClass}">${escapeHtml(ev.risk_level)}</span></td>
          <td>${baselineAction}</td>
        </tr>
      `;
    });

    elements.tbodyLive.innerHTML = rowsHtml;

    // Attach row click handlers to select event for Behavioral Analysis
    const rows = elements.tbodyLive.querySelectorAll('.event-row');
    rows.forEach(r => {
      r.addEventListener('click', () => {
        const id = parseInt(r.getAttribute('data-id'), 10);
        const ev = state.allLiveEvents.find(e => e.id === id);
        if (ev) {
          state.selectedEvent = ev;
          updateBehavioralGauges(ev);
        }
      });
    });
  }

  // ========================================================================
  // Section 3: Behavioral Analysis Rendering
  // ========================================================================

  function updateBehavioralGauges(ev) {
    if (!ev) return;

    if (elements.behaviorSelectedLabel) {
      elements.behaviorSelectedLabel.textContent = `Inspecting: ${truncate(ev.domain, 35)} (${ev.host})`;
    }
    if (elements.behaviorMetaHost) elements.behaviorMetaHost.textContent = ev.host;
    if (elements.behaviorMetaDomain) elements.behaviorMetaDomain.textContent = truncate(ev.domain, 40);
    if (elements.behaviorMetaScore) {
      const score = Number.isFinite(Number(ev.behavior_score)) ? Number(ev.behavior_score) : 0.0;
      elements.behaviorMetaScore.textContent = score.toFixed(1);
      elements.behaviorMetaScore.className = score >= 70 ? 'meta-val font-mono font-bold text-danger' :
                                            score >= 50 ? 'meta-val font-mono font-bold text-warning' :
                                            'meta-val font-mono font-bold text-success';
    }
    if (elements.behaviorMetaConf) elements.behaviorMetaConf.textContent = formatPercent(ev.confidence, 0, 'N/A');

    // 5-Tier deviation values supplied by backend
    const pEntropy = Math.min(100, ((Number(ev.entropy_deviation) || 0) * 100));
    const pLength = Math.min(100, ((Number(ev.domain_length_deviation) || 0) * 100));
    const pRate = Math.min(100, ((Number(ev.query_rate_deviation) || 0) * 100));
    const pNovel = Math.min(100, ((Number(ev.novel_domain_score) || 0) * 100));
    const pOrg = Math.min(100, ((Number(ev.organization_rarity_score) || 0) * 100));

    if (elements.tierBarEntropy) elements.tierBarEntropy.style.width = `${pEntropy}%`;
    if (elements.tierBarLength) elements.tierBarLength.style.width = `${pLength}%`;
    if (elements.tierBarRate) elements.tierBarRate.style.width = `${pRate}%`;
    if (elements.tierBarNovel) elements.tierBarNovel.style.width = `${pNovel}%`;
    if (elements.tierBarOrg) elements.tierBarOrg.style.width = `${pOrg}%`;

    if (elements.tierValEntropy) elements.tierValEntropy.textContent = `Deviation: ${formatNumber(ev.entropy_deviation, 4, '0.0000')} | Raw Entropy: ${formatNumber(ev.entropy, 4, '0.0000')} bits`;
    if (elements.tierValLength) elements.tierValLength.textContent = `Deviation: ${formatNumber(ev.domain_length_deviation, 4, '0.0000')} | Raw Length: ${ev.domain_length != null ? ev.domain_length : 0} chars`;
    if (elements.tierValRate) elements.tierValRate.textContent = `Deviation: ${formatNumber(ev.query_rate_deviation, 4, '0.0000')} | Observed Rate: ${formatNumber(ev.query_rate, 2, '0.00')} QPS`;
    if (elements.tierValNovel) elements.tierValNovel.textContent = `Deviation: ${formatNumber(ev.novel_domain_score, 4, '0.0000')} | Host Novelty Metric`;
    if (elements.tierValOrg) elements.tierValOrg.textContent = `Deviation: ${formatNumber(ev.organization_rarity_score, 4, '0.0000')} | Enterprise Inverse Rarity Metric`;

    // Sliding window QPS box
    if (elements.swRateVal) {
      elements.swRateVal.textContent = `${formatNumber(ev.query_rate, 2, '0.00')} QPS`;
    }
    if (elements.swBurstStatus) {
      const qrate = Number(ev.query_rate) || 0;
      if (qrate > 2.0) {
        elements.swBurstStatus.innerHTML = '<span class="pill-dot" style="background-color: #f59e0b;"></span> <span style="color: #f59e0b;">Burst Rate Exceeds 2.0 QPS Baseline</span>';
      } else {
        elements.swBurstStatus.innerHTML = '<span class="pill-dot"></span> <span>Normal Temporal Traffic Pace (&le; 2.0 QPS)</span>';
      }
    }
  }

  // ========================================================================
  // Section 4: Host View Management
  // ========================================================================

  function loadHostList() {
    fetch('/api/hosts')
      .then(r => r.json())
      .then(hosts => {
        if (!elements.selectHostProfile) return;
        elements.selectHostProfile.innerHTML = '';
        if (hosts.length === 0) {
          elements.selectHostProfile.innerHTML = '<option value="">No host profiles registered</option>';
          elements.hostDetailsView.classList.add('hidden');
          elements.hostEmptyState.classList.remove('hidden');
          return;
        }

        elements.hostEmptyState.classList.add('hidden');
        elements.hostDetailsView.classList.remove('hidden');

        hosts.forEach(h => {
          const opt = document.createElement('option');
          opt.value = h.host;
          opt.textContent = `${h.host} (${h.total_queries} queries)`;
          elements.selectHostProfile.appendChild(opt);
        });

        // Render All Monitored Hosts Cards Grid
        if (elements.hostsCardsGrid) {
          let cardsHtml = '';
          hosts.forEach(h => {
            cardsHtml += `
              <div class="host-summary-card" data-host="${escapeHtml(h.host)}">
                <div class="host-summary-header">
                  <span class="host-summary-ip">${escapeHtml(h.host)}</span>
                  <span class="badge badge-secondary" style="font-size: 0.72rem;">${h.total_queries} Queries</span>
                </div>
                <div class="host-summary-metric">
                  <span>Avg Entropy:</span> <strong class="font-mono">${h.average_entropy.toFixed(4)}</strong>
                </div>
                <div class="host-summary-metric">
                  <span>Avg Length:</span> <strong class="font-mono">${h.average_domain_length.toFixed(1)}</strong>
                </div>
                <div class="host-summary-metric">
                  <span>Status:</span> <span class="badge badge-normal" style="font-size: 0.68rem;">${escapeHtml(h.calibration_state || 'Calibrated')}</span>
                </div>
              </div>
            `;
          });
          elements.hostsCardsGrid.innerHTML = cardsHtml;

          // Attach card click handlers
          const hostCards = elements.hostsCardsGrid.querySelectorAll('.host-summary-card');
          hostCards.forEach(c => {
            c.addEventListener('click', () => {
              const hIp = c.getAttribute('data-host');
              if (hIp) {
                state.selectedHost = hIp;
                elements.selectHostProfile.value = hIp;
                loadHostProfile(hIp);
              }
            });
          });
        }

        if (!state.selectedHost && hosts.length > 0) {
          state.selectedHost = hosts[0].host;
        }
        if (state.selectedHost) {
          elements.selectHostProfile.value = state.selectedHost;
          loadHostProfile(state.selectedHost);
        }
      })
      .catch(() => {});
  }

  function loadHostProfile(hostIp) {
    fetch(`/api/host/${encodeURIComponent(hostIp)}`)
      .then(r => r.json())
      .then(details => {
        if (!details || details.error) return;

        if (elements.hostDisplayIp) elements.hostDisplayIp.textContent = `Host Profile: ${hostIp}`;
        if (elements.hostCalibrationState) {
          elements.hostCalibrationState.textContent = details.calibration_state || 'Steady-State Baseline';
        }
        if (elements.hostTotalQ) elements.hostTotalQ.textContent = details.total_queries.toLocaleString();
        if (elements.hostAvgEntropy) elements.hostAvgEntropy.textContent = details.average_entropy.toFixed(4);
        if (elements.hostAvgLength) elements.hostAvgLength.textContent = details.average_domain_length.toFixed(2);
        if (elements.hostUniqueDomains) elements.hostUniqueDomains.textContent = (details.unique_domains || []).length;

        // Top domains
        let domHtml = '';
        (details.top_domains || []).forEach(d => {
          domHtml += `
            <tr>
              <td class="font-mono">${escapeHtml(d.domain)}</td>
              <td class="font-mono"><strong>${d.count}</strong></td>
            </tr>
          `;
        });
        if (elements.tbodyHostDomains) {
          elements.tbodyHostDomains.innerHTML = domHtml || '<tr><td colspan="2">No domain records</td></tr>';
        }

        // Query Types
        let qTypesHtml = '';
        const qTypes = details.query_type_frequency || {};
        for (const [k, v] of Object.entries(qTypes)) {
          const name = getQueryTypeName(parseInt(k, 10));
          qTypesHtml += `<div class="chip">Type ${k} (${name}): <strong>${v}</strong></div>`;
        }
        if (elements.hostQueryTypes) {
          elements.hostQueryTypes.innerHTML = qTypesHtml || '<span class="text-muted">No query type records</span>';
        }
      })
      .catch(() => {});
  }

  // ========================================================================
  // Section 5: Alert View Rendering
  // ========================================================================

  function renderAlertsTable(alerts) {
    let filtered = alerts;
    if (state.alertSeverityFilter === 'HIGH_RISK') {
      filtered = alerts.filter(a => a.risk_level === 'HIGH_RISK');
    } else if (state.alertSeverityFilter === 'SUSPICIOUS') {
      filtered = alerts.filter(a => a.risk_level === 'SUSPICIOUS');
    }

    if (filtered.length === 0) {
      elements.tbodyAlerts.innerHTML = '';
      elements.alertsEmptyState.classList.remove('hidden');
      return;
    }

    elements.alertsEmptyState.classList.add('hidden');
    let rowsHtml = '';

    filtered.forEach(al => {
      const riskClass = getRiskBadgeClass(al.risk_level);
      const devSummary = `H: ${formatNumber(al.entropy, 2, '0.00')}, L: ${al.domain_length != null && Number.isFinite(Number(al.domain_length)) ? Number(al.domain_length) : 0}, R: ${formatNumber(al.query_rate, 1, '0.0')}`;
      const detectionMethodHtml = formatDetectionMethod(al);
      const baselineAction = formatBaselineStatus(al);

      rowsHtml += `
        <tr class="alert-row" data-id="${al.id}" style="cursor: pointer;">
          <td class="font-mono">${formatTimestamp(al.timestamp)}</td>
          <td class="font-mono"><strong>${escapeHtml(al.host)}</strong></td>
          <td class="font-mono" style="color: #fca5a5;"><strong>${escapeHtml(truncate(al.domain, 35))}</strong></td>
          <td class="font-mono"><strong class="text-danger">${formatNumber(al.behavior_score, 1, '0.0')}</strong></td>
          <td>${detectionMethodHtml}</td>
          <td><span class="badge ${riskClass}">${escapeHtml(al.risk_level)}</span></td>
          <td class="font-mono">${formatPercent(al.confidence, 0, 'N/A')}</td>
          <td>${baselineAction}</td>
          <td class="font-mono" style="font-size: 0.76rem; color: #a5f3fc;">${escapeHtml(devSummary)}</td>
          <td style="font-size: 0.78rem; color: #cbd5e1;"><em>Analyst Guidance:</em> ${escapeHtml(al.recommendation)}</td>
        </tr>
      `;
    });

    elements.tbodyAlerts.innerHTML = rowsHtml;

    // Attach row click to inspect in Behavioral Analysis
    const rows = elements.tbodyAlerts.querySelectorAll('.alert-row');
    rows.forEach(r => {
      r.addEventListener('click', () => {
        const id = parseInt(r.getAttribute('data-id'), 10);
        const ev = state.allAlerts.find(e => e.id === id);
        if (ev) {
          state.selectedEvent = ev;
          updateBehavioralGauges(ev);
        }
      });
    });
  }

  // ========================================================================
  // Section 6: Research Benchmarks (Phase 7B Publication Artifacts)
  // ========================================================================

  function loadResearchResults() {
    fetch('/api/research')
      .then(r => r.json())
      .then(res => {
        // 1. TunnelEye Dataset-Level Reproduction
        const te = res.tunneleye_baseline;
        if (te && te.datasets && elements.tbodyTunnelEye) {
          let teHtml = '';
          te.datasets.forEach(ds => {
            teHtml += `
              <tr>
                <td><strong>${escapeHtml(ds.split_id)}</strong></td>
                <td>${escapeHtml(ds.dataset_name)}</td>
                <td>${escapeHtml(ds.direction)}</td>
                <td class="font-mono"><strong>${ds.accuracy.toFixed(10)}</strong></td>
                <td class="font-mono">${ds.weighted_precision.toFixed(10)}</td>
                <td class="font-mono">${ds.weighted_recall.toFixed(10)}</td>
                <td class="font-mono">${ds.weighted_f1.toFixed(10)}</td>
                <td><span class="badge badge-secondary">${te.latency}</span></td>
              </tr>
            `;
          });

          // Macro average
          if (te.macro_average) {
            const m = te.macro_average;
            teHtml += `
              <tr style="background-color: rgba(59, 130, 246, 0.08); font-weight: 700;">
                <td><strong>Macro Average</strong></td>
                <td>4 Datasets Pooled</td>
                <td>Bidirectional Mean</td>
                <td class="font-mono"><strong>${m.accuracy.toFixed(10)}</strong></td>
                <td class="font-mono">${m.weighted_precision.toFixed(10)}</td>
                <td class="font-mono">${m.weighted_recall.toFixed(10)}</td>
                <td class="font-mono">${m.weighted_f1.toFixed(10)}</td>
                <td><span class="badge badge-secondary">${te.latency}</span></td>
              </tr>
            `;
          }
          elements.tbodyTunnelEye.innerHTML = teHtml;
        }

        // 2. Feature Sensitivity Analysis (Ablation)
        const abl = res.ablation_study;
        if (abl && abl.length > 0 && elements.tbodyAblation) {
          let ablHtml = '';
          abl.forEach(row => {
            ablHtml += `
              <tr>
                <td><strong>${escapeHtml(row.tier.split(':')[0])}</strong></td>
                <td>${escapeHtml(row.tier)}</td>
                <td class="font-mono" style="font-size: 0.74rem;">${escapeHtml(row.weights)}</td>
                <td class="font-mono">${parseFloat(row.accuracy).toFixed(4)}</td>
                <td class="font-mono">${parseFloat(row.binary_precision).toFixed(4)}</td>
                <td class="font-mono">${parseFloat(row.binary_recall).toFixed(4)}</td>
                <td class="font-mono"><strong>${parseFloat(row.binary_f1).toFixed(4)}</strong></td>
                <td class="font-mono">${parseFloat(row.false_positive_rate).toFixed(4)}</td>
              </tr>
            `;
          });
          elements.tbodyAblation.innerHTML = ablHtml;
        }
      })
      .catch(() => {});
  }

  // ========================================================================
  // Action Handlers
  // ========================================================================

  function triggerReplay(traceType) {
    let btn;
    if (traceType === 'benign') {
      btn = elements.btnReplayBenign;
    } else if (traceType === 'benign_mature') {
      btn = elements.btnReplayBenignMature;
    } else if (traceType === 'tunnel_b') {
      btn = elements.btnReplayTunnelB;
    } else if (traceType === 'tunnel_cascade') {
      btn = elements.btnReplayTunnelCascade;
    } else {
      btn = elements.btnReplayTunnel;
    }
    if (!btn) return;
    const origText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span>⏳</span> Processing Sandbox Replay...';

    fetch('/api/replay', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ trace: traceType, max_records: 150 })
    })
      .then(r => r.json())
      .then(data => {
        btn.disabled = false;
        btn.innerHTML = origText;
        pollCycle();
      })
      .catch(() => {
        btn.disabled = false;
        btn.innerHTML = origText;
      });
  }

  function submitCustomTest() {
    const input = elements.customDomainInput;
    const domain = input.value.trim();
    if (!domain) return;

    elements.btnTestCustom.disabled = true;
    fetch('/api/test_query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: domain, host: '10.0.0.1', query_type: 1 })
    })
      .then(async r => {
        const data = await r.json().catch(() => ({}));
        if (!r.ok || data.error) {
          const errMsg = data.error || `Request failed (${r.status})`;
          alert(errMsg);
          return;
        }
        input.value = '';
        pollCycle();
      })
      .catch(err => {
        alert(err.message || 'Failed to submit test query');
      })
      .finally(() => {
        elements.btnTestCustom.disabled = false;
      });
  }

  function clearFeed() {
    fetch('/api/clear', { method: 'POST' })
      .then(() => {
        state.selectedEvent = null;
        pollCycle();
      })
      .catch(() => {});
  }

  function exportAlertsCSV() {
    fetch('/api/alerts?limit=200')
      .then(r => r.json())
      .then(alerts => {
        if (!alerts || alerts.length === 0) {
          alert('No alerts currently in buffer to export.');
          return;
        }
        let csvContent = 'data:text/csv;charset=utf-8,';
        csvContent += 'Timestamp,Host,Domain,Score,Risk_Level,Confidence,Baseline_Protected,Recommendation\r\n';

        alerts.forEach(a => {
          const recText = a.recommendation ? String(a.recommendation).replace(/"/g, '""') : '';
          const row = [
            `"${a.timestamp || ''}"`,
            `"${a.host || ''}"`,
            `"${a.domain || ''}"`,
            a.behavior_score != null ? a.behavior_score : 0,
            `"${a.risk_level || 'NORMAL'}"`,
            a.confidence != null ? a.confidence : 0,
            !a.baseline_updated,
            `"${recText}"`
          ].join(',');
          csvContent += row + '\r\n';
        });

        const encodedUri = encodeURI(csvContent);
        const link = document.createElement('a');
        link.setAttribute('href', encodedUri);
        link.setAttribute('download', `dnsentinel_alerts_${new Date().toISOString().slice(0, 10)}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      });
  }

  // ========================================================================
  // Utility Functions
  // ========================================================================

  function getRiskBadgeClass(level) {
    switch (level) {
      case 'NORMAL': return 'badge-normal';
      case 'LOW_RISK': return 'badge-low';
      case 'SUSPICIOUS': return 'badge-suspicious';
      case 'HIGH_RISK': return 'badge-high';
      default: return 'badge-secondary';
    }
  }

  function getQueryTypeName(qtype) {
    const map = { 1: 'A', 28: 'AAAA', 16: 'TXT', 15: 'MX', 5: 'CNAME', 12: 'PTR', 2: 'NS' };
    return map[qtype] || `TYPE_${qtype}`;
  }

  function formatTimestamp(isoStr) {
    if (!isoStr) return '-';
    try {
      const d = new Date(isoStr);
      if (isNaN(d.getTime())) return isoStr;
      return d.toLocaleTimeString() + '.' + String(d.getMilliseconds()).padStart(3, '0');
    } catch {
      return isoStr;
    }
  }

  function formatTimeOnly(isoStr) {
    try {
      const d = new Date(isoStr);
      return isNaN(d.getTime()) ? isoStr : d.toLocaleTimeString();
    } catch {
      return isoStr;
    }
  }

  function truncate(str, maxLen) {
    if (!str) return '';
    return str.length > maxLen ? str.slice(0, maxLen) + '...' : str;
  }

  function formatNumber(val, decimals = 1, fallback = '0.0') {
    if (val === null || val === undefined) return fallback;
    const num = Number(val);
    if (!Number.isFinite(num)) return fallback;
    return num.toFixed(decimals);
  }

  function formatPercent(val, decimals = 0, fallback = 'N/A') {
    if (val === null || val === undefined) return fallback;
    const num = Number(val);
    if (!Number.isFinite(num)) return fallback;
    const pct = num <= 1.0 && num >= 0.0 ? num * 100 : num;
    return `${pct.toFixed(decimals)}%`;
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Run on DOM Ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
