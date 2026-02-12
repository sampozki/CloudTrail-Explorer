const state = {
  allEvents: [],
  filteredEvents: [],
  pagedEvents: [],
  selectedIndex: -1,
  currentPage: 1,
  sortBy: 'eventTime',
  sortDir: 'desc',
  timeMode: 'utc',
  paneLayout: 'side',
  paneVisibility: 'both',
  splitRatioSide: 50,
  splitRatioStack: 50,
  controlsHidden: false,
  loadedFileName: null,
};
const LAST_FILE_STORAGE_KEY = 'cloudtrailExplorer.lastFile';

const layoutRoot = document.getElementById('layoutRoot');
const fileInput = document.getElementById('fileInput');
const clearBtn = document.getElementById('clearBtn');
const toggleControlsBtn = document.getElementById('toggleControlsBtn');
const showControlsFab = document.getElementById('showControlsFab');
const searchInput = document.getElementById('searchInput');
const eventSourceInput = document.getElementById('eventSourceInput');
const eventNameInput = document.getElementById('eventNameInput');
const usernameInput = document.getElementById('usernameInput');
const regionInput = document.getElementById('regionInput');
const errorOnlyInput = document.getElementById('errorOnlyInput');
const limitInput = document.getElementById('limitInput');
const paneLayoutInput = document.getElementById('paneLayoutInput');
const paneVisibilityInput = document.getElementById('paneVisibilityInput');
const timeModeBtn = document.getElementById('timeModeBtn');
const paneSplitter = document.getElementById('paneSplitter');
const eventsTable = document.getElementById('eventsTable');
const eventsBody = document.getElementById('eventsBody');
const rowTemplate = document.getElementById('rowTemplate');
const firstPageBtn = document.getElementById('firstPageBtn');
const prevPageBtn = document.getElementById('prevPageBtn');
const nextPageBtn = document.getElementById('nextPageBtn');
const lastPageBtn = document.getElementById('lastPageBtn');
const pageInfo = document.getElementById('pageInfo');
const detailsPanel = document.getElementById('detailsPanel');
const resultsCount = document.getElementById('resultsCount');
const detailHint = document.getElementById('detailHint');
const metaRow = document.getElementById('metaRow');
const headers = Array.from(document.querySelectorAll('th[data-sort]'));
const eventSourceSuggestions = document.getElementById('eventSourceSuggestions');
const eventNameSuggestions = document.getElementById('eventNameSuggestions');
const usernameSuggestions = document.getElementById('usernameSuggestions');
const regionSuggestions = document.getElementById('regionSuggestions');
const colTime = document.getElementById('colTime');
const colSource = document.getElementById('colSource');
const colEvent = document.getElementById('colEvent');
const colUser = document.getElementById('colUser');
const colRegion = document.getElementById('colRegion');
const colStatus = document.getElementById('colStatus');

const safeText = (value) => (value == null || value === '' ? '-' : String(value));
const isWideScreen = () => window.matchMedia('(min-width: 1100px)').matches;
const escapeHtml = (text) =>
  String(text)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');

function syntaxHighlightJson(value) {
  const json = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  const escaped = escapeHtml(json);
  const tokenRegex =
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"\s*:|"(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?|\btrue\b|\bfalse\b|\bnull\b)/g;

  return escaped.replace(tokenRegex, (match) => {
    let type = 'number';
    if (match.startsWith('"') && match.endsWith(':')) {
      type = 'key';
    } else if (match.startsWith('"')) {
      type = 'string';
    } else if (match === 'true' || match === 'false') {
      type = 'boolean';
    } else if (match === 'null') {
      type = 'null';
    }
    return `<span class="json-${type}">${match}</span>`;
  });
}

function formatTime(ms, fallback) {
  if (!ms) return safeText(fallback);
  if (state.timeMode === 'local') {
    return new Date(ms).toLocaleString([], {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  }
  return new Date(ms).toISOString();
}

function extractPrincipal(event) {
  const ui = event.userIdentity || {};
  return (
    ui.userName ||
    ui.arn ||
    ui.principalId ||
    ui.sessionContext?.sessionIssuer?.arn ||
    ui.sessionContext?.sessionIssuer?.userName ||
    event.username ||
    '-'
  );
}

function parseCloudTrail(raw) {
  if (!raw || typeof raw !== 'object') throw new Error('JSON root must be object or array');
  if (Array.isArray(raw)) return raw;
  if (Array.isArray(raw.Records)) return raw.Records;
  if (Array.isArray(raw.records)) return raw.records;
  if (Array.isArray(raw.events)) return raw.events;
  throw new Error('No event array found. Expected Records/events/records or top-level array.');
}

function saveLastFileToStorage(fileName, text) {
  try {
    localStorage.setItem(
      LAST_FILE_STORAGE_KEY,
      JSON.stringify({
        fileName,
        text,
        savedAtMs: Date.now(),
      })
    );
  } catch (err) {
    console.warn('Unable to save file to localStorage:', err);
  }
}

function clearLastFileFromStorage() {
  try {
    localStorage.removeItem(LAST_FILE_STORAGE_KEY);
  } catch (err) {
    console.warn('Unable to clear localStorage:', err);
  }
}

function normalizeEvent(evt, idx) {
  const principal = extractPrincipal(evt);
  const error = evt.errorCode || evt.errorMessage;
  const time = evt.eventTime || evt.eventDate || evt.timestamp || '';
  const fullJsonText = JSON.stringify(evt).toLowerCase();
  return {
    __idx: idx,
    raw: evt,
    eventTime: time,
    eventTimeMs: Date.parse(time) || 0,
    eventSource: evt.eventSource || evt.sourceIPAddress || '',
    eventName: evt.eventName || evt.eventType || '',
    userIdentity: principal,
    awsRegion: evt.awsRegion || evt.region || '',
    errorCode: error || '',
    searchBlob: [
      evt.eventID,
      evt.requestID,
      evt.eventSource,
      evt.eventName,
      principal,
      evt.sourceIPAddress,
      evt.userAgent,
      evt.awsRegion,
      evt.errorCode,
      evt.errorMessage,
      JSON.stringify(evt.resources || []),
      fullJsonText,
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase(),
  };
}

function getPageSize() {
  if (limitInput.value === 'all') {
    return Math.max(1, state.filteredEvents.length);
  }
  return Number(limitInput.value) || 100;
}

function applyColumnVisibility() {
  eventsTable.classList.toggle('hide-col-time', !colTime.checked);
  eventsTable.classList.toggle('hide-col-source', !colSource.checked);
  eventsTable.classList.toggle('hide-col-event', !colEvent.checked);
  eventsTable.classList.toggle('hide-col-user', !colUser.checked);
  eventsTable.classList.toggle('hide-col-region', !colRegion.checked);
  eventsTable.classList.toggle('hide-col-status', !colStatus.checked);
}

function fillDatalist(datalist, values, limit = 300) {
  const uniqueSorted = Array.from(new Set(values.filter(Boolean))).sort((a, b) => a.localeCompare(b));
  datalist.innerHTML = '';
  uniqueSorted.slice(0, limit).forEach((value) => {
    const option = document.createElement('option');
    option.value = value;
    datalist.appendChild(option);
  });
}

function updateAutocompleteSuggestions() {
  fillDatalist(
    eventSourceSuggestions,
    state.allEvents.map((e) => e.eventSource)
  );
  fillDatalist(
    eventNameSuggestions,
    state.allEvents.map((e) => e.eventName)
  );
  fillDatalist(
    usernameSuggestions,
    state.allEvents.map((e) => e.userIdentity)
  );
  fillDatalist(
    regionSuggestions,
    state.allEvents.map((e) => e.awsRegion)
  );
}

function applyFilters() {
  const rawQuery = searchInput.value.trim().toLowerCase();
  const hasNegationPrefix = rawQuery.startsWith('!');
  const parsedQuery = hasNegationPrefix ? rawQuery.slice(1).trim() : rawQuery;
  const hasSearchQuery = parsedQuery.length > 0;
  const isNegatedQuery = hasNegationPrefix && hasSearchQuery;
  const query = parsedQuery;
  const source = eventSourceInput.value.trim().toLowerCase();
  const eventName = eventNameInput.value.trim().toLowerCase();
  const user = usernameInput.value.trim().toLowerCase();
  const region = regionInput.value.trim().toLowerCase();
  const errorMode = errorOnlyInput.value;

  let rows = state.allEvents.filter((evt) => {
    if (hasSearchQuery) {
      const matchesQuery = evt.searchBlob.includes(query);
      if (!isNegatedQuery && !matchesQuery) return false;
      if (isNegatedQuery && matchesQuery) return false;
    }
    if (source && !evt.eventSource.toLowerCase().includes(source)) return false;
    if (eventName && !evt.eventName.toLowerCase().includes(eventName)) return false;
    if (user && !evt.userIdentity.toLowerCase().includes(user)) return false;
    if (region && !evt.awsRegion.toLowerCase().includes(region)) return false;

    if (errorMode === 'errors' && !evt.errorCode) return false;
    if (errorMode === 'success' && evt.errorCode) return false;

    return true;
  });

  rows.sort((a, b) => {
    const direction = state.sortDir === 'asc' ? 1 : -1;

    if (state.sortBy === 'eventTime') {
      return (a.eventTimeMs - b.eventTimeMs) * direction;
    }

    const left = safeText(a[state.sortBy]).toLowerCase();
    const right = safeText(b[state.sortBy]).toLowerCase();
    if (left < right) return -1 * direction;
    if (left > right) return 1 * direction;
    return 0;
  });

  state.filteredEvents = rows;
  paginateResults();
}

function paginateResults() {
  const pageSize = getPageSize();
  const totalPages = Math.max(1, Math.ceil(state.filteredEvents.length / pageSize));
  state.currentPage = clamp(state.currentPage, 1, totalPages);

  const start = (state.currentPage - 1) * pageSize;
  const end = start + pageSize;
  state.pagedEvents = state.filteredEvents.slice(start, end);
  renderTable();
}

function renderTable() {
  eventsBody.innerHTML = '';

  const count = state.pagedEvents.length;
  const total = state.allEvents.length;
  const filteredTotal = state.filteredEvents.length;
  resultsCount.textContent = `${filteredTotal} results (of ${total})`;

  const pageSize = getPageSize();
  const totalPages = Math.max(1, Math.ceil(filteredTotal / pageSize));
  pageInfo.textContent = `Page ${state.currentPage} / ${totalPages}`;
  firstPageBtn.disabled = state.currentPage <= 1;
  prevPageBtn.disabled = state.currentPage <= 1;
  nextPageBtn.disabled = state.currentPage >= totalPages;
  lastPageBtn.disabled = state.currentPage >= totalPages;

  state.pagedEvents.forEach((evt, i) => {
    const tr = rowTemplate.content.firstElementChild.cloneNode(true);

    tr.querySelector('.time').textContent = formatTime(evt.eventTimeMs, evt.eventTime);
    tr.querySelector('.source').textContent = safeText(evt.eventSource);
    tr.querySelector('.name').textContent = safeText(evt.eventName);
    tr.querySelector('.user').textContent = safeText(evt.userIdentity);
    tr.querySelector('.region').textContent = safeText(evt.awsRegion);

    const statusCell = tr.querySelector('.status');
    if (evt.errorCode) {
      statusCell.textContent = safeText(evt.errorCode);
      statusCell.classList.add('status-error');
    } else {
      statusCell.textContent = 'OK';
      statusCell.classList.add('status-ok');
    }

    tr.addEventListener('click', () => selectEvent(i));
    eventsBody.appendChild(tr);
  });

  if (state.pagedEvents.length > 0) {
    selectEvent(0);
  } else {
    state.selectedIndex = -1;
    detailsPanel.textContent = 'No event selected.';
    detailHint.textContent = 'Select an event';
  }
}

function selectEvent(index) {
  if (state.paneVisibility === 'hide-details') {
    state.paneVisibility = 'both';
    paneVisibilityInput.value = 'both';
    applyPaneLayoutMode();
  }

  state.selectedIndex = index;
  Array.from(eventsBody.children).forEach((row, i) => {
    row.classList.toggle('active', i === index);
  });

  const evt = state.pagedEvents[index];
  if (!evt) {
    detailsPanel.textContent = 'No event selected.';
    detailHint.textContent = 'Select an event';
    return;
  }

  detailsPanel.innerHTML = syntaxHighlightJson(evt.raw);
  const id = evt.raw.eventID || evt.raw.requestID || evt.raw.sharedEventID || 'n/a';
  detailHint.textContent = `eventID/requestID: ${id}`;
}

function updateMetaRow() {
  if (!state.loadedFileName) {
    metaRow.textContent = 'No file loaded.';
    return;
  }

  const total = state.allEvents.length;
  const withErrors = state.allEvents.filter((e) => e.errorCode).length;
  const first = state.allEvents.reduce((acc, item) => (item.eventTimeMs && item.eventTimeMs < acc ? item.eventTimeMs : acc), Number.MAX_SAFE_INTEGER);
  const last = state.allEvents.reduce((acc, item) => (item.eventTimeMs > acc ? item.eventTimeMs : acc), 0);

  const firstText = first === Number.MAX_SAFE_INTEGER ? '-' : formatTime(first, '-');
  const lastText = last === 0 ? '-' : formatTime(last, '-');

  metaRow.textContent = `Loaded: ${state.loadedFileName} | Events: ${total} | Errors: ${withErrors} | Range: ${firstText} .. ${lastText}`;
}

function setTimeMode(mode) {
  state.timeMode = mode;
  timeModeBtn.textContent = mode === 'utc' ? 'UTC' : 'Local';
  timeModeBtn.setAttribute('aria-pressed', String(mode === 'local'));
  renderTable();
  updateMetaRow();
}

function applyPaneLayoutMode() {
  const hideEvents = state.paneVisibility === 'hide-events';
  const hideDetails = state.paneVisibility === 'hide-details';
  layoutRoot.classList.toggle('layout-stacked', state.paneLayout === 'stack');
  layoutRoot.classList.toggle('events-hidden', hideEvents);
  layoutRoot.classList.toggle('details-hidden', hideDetails);

  if (hideEvents || hideDetails) {
    layoutRoot.style.gridTemplateColumns = '';
    layoutRoot.style.gridTemplateRows = '';
    return;
  }

  if (!isWideScreen()) {
    layoutRoot.style.gridTemplateColumns = '';
    layoutRoot.style.gridTemplateRows = '';
    return;
  }

  if (state.paneLayout === 'side') {
    const left = state.splitRatioSide;
    const right = 100 - left;
    layoutRoot.style.gridTemplateColumns = `${left}fr 10px ${right}fr`;
    layoutRoot.style.gridTemplateRows = '';
  } else {
    const top = state.splitRatioStack;
    const bottom = 100 - top;
    layoutRoot.style.gridTemplateColumns = '1fr';
    layoutRoot.style.gridTemplateRows = `auto ${top}fr 10px ${bottom}fr`;
  }
}

function applyControlsVisibility() {
  document.body.classList.toggle('controls-hidden', state.controlsHidden);
  toggleControlsBtn.textContent = state.controlsHidden ? 'Show Controls' : 'Hide Controls';
  applyPaneLayoutMode();
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function updateSplitFromPointer(clientX, clientY) {
  const rect = layoutRoot.getBoundingClientRect();
  if (state.paneLayout === 'side') {
    const ratio = ((clientX - rect.left) / rect.width) * 100;
    state.splitRatioSide = clamp(ratio, 20, 80);
  } else {
    const controlsHeight = document.querySelector('.controls')?.getBoundingClientRect().height || 0;
    const topBoundary = rect.top + controlsHeight;
    const usableHeight = Math.max(1, rect.bottom - topBoundary);
    const ratio = ((clientY - topBoundary) / usableHeight) * 100;
    state.splitRatioStack = clamp(ratio, 20, 80);
  }
  applyPaneLayoutMode();
}

function reset() {
  state.allEvents = [];
  state.filteredEvents = [];
  state.pagedEvents = [];
  state.selectedIndex = -1;
  state.currentPage = 1;
  state.loadedFileName = null;
  eventsBody.innerHTML = '';
  detailsPanel.textContent = 'No event selected.';
  resultsCount.textContent = '0 results';
  pageInfo.textContent = 'Page 1 / 1';
  firstPageBtn.disabled = true;
  prevPageBtn.disabled = true;
  nextPageBtn.disabled = true;
  lastPageBtn.disabled = true;
  detailHint.textContent = 'Select an event';
  updateMetaRow();
  updateAutocompleteSuggestions();
}

async function handleFileUpload(file) {
  if (!file) return;

  const text = await file.text();
  loadFromJsonText(text, file.name, true);
}

function loadFromJsonText(text, fileName, shouldPersist) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    alert('Invalid JSON file.');
    return;
  }

  let events;
  try {
    events = parseCloudTrail(parsed);
  } catch (err) {
    alert(err.message);
    return;
  }

  state.allEvents = events.map(normalizeEvent);
  state.loadedFileName = fileName;
  updateMetaRow();
  updateAutocompleteSuggestions();
  applyFilters();

  if (shouldPersist) {
    saveLastFileToStorage(fileName, text);
  }
}

function restoreLastFileFromStorage() {
  let raw = null;
  try {
    raw = localStorage.getItem(LAST_FILE_STORAGE_KEY);
  } catch (err) {
    console.warn('Unable to read localStorage:', err);
    return;
  }

  if (!raw) return;

  try {
    const saved = JSON.parse(raw);
    if (!saved || typeof saved.text !== 'string') {
      clearLastFileFromStorage();
      return;
    }
    const restoredName = saved.fileName || 'restored-cloudtrail.json';
    loadFromJsonText(saved.text, restoredName, false);
  } catch {
    clearLastFileFromStorage();
  }
}

fileInput.addEventListener('change', (e) => {
  const file = e.target.files[0];
  handleFileUpload(file);
});

clearBtn.addEventListener('click', () => {
  fileInput.value = '';
  searchInput.value = '';
  eventSourceInput.value = '';
  eventNameInput.value = '';
  usernameInput.value = '';
  regionInput.value = '';
  errorOnlyInput.value = 'all';
  limitInput.value = '100';
  clearLastFileFromStorage();
  reset();
});

[searchInput, eventSourceInput, eventNameInput, usernameInput, regionInput].forEach((el) => {
  el.addEventListener('input', () => {
    state.currentPage = 1;
    applyFilters();
  });
});

[errorOnlyInput, limitInput].forEach((el) => {
  el.addEventListener('change', () => {
    state.currentPage = 1;
    applyFilters();
  });
});

timeModeBtn.addEventListener('click', () => {
  setTimeMode(state.timeMode === 'utc' ? 'local' : 'utc');
});
toggleControlsBtn.addEventListener('click', () => {
  state.controlsHidden = !state.controlsHidden;
  applyControlsVisibility();
});
showControlsFab.addEventListener('click', () => {
  state.controlsHidden = false;
  applyControlsVisibility();
});
paneLayoutInput.addEventListener('change', () => {
  state.paneLayout = paneLayoutInput.value;
  applyPaneLayoutMode();
});
paneVisibilityInput.addEventListener('change', () => {
  state.paneVisibility = paneVisibilityInput.value;
  applyPaneLayoutMode();
});
firstPageBtn.addEventListener('click', () => {
  state.currentPage = 1;
  paginateResults();
});
prevPageBtn.addEventListener('click', () => {
  state.currentPage -= 1;
  paginateResults();
});
nextPageBtn.addEventListener('click', () => {
  state.currentPage += 1;
  paginateResults();
});
lastPageBtn.addEventListener('click', () => {
  const pageSize = getPageSize();
  const totalPages = Math.max(1, Math.ceil(state.filteredEvents.length / pageSize));
  state.currentPage = totalPages;
  paginateResults();
});

[colTime, colSource, colEvent, colUser, colRegion, colStatus].forEach((checkbox) => {
  checkbox.addEventListener('change', applyColumnVisibility);
});

paneSplitter.addEventListener('pointerdown', (event) => {
  if (state.paneVisibility !== 'both' || !isWideScreen()) return;

  paneSplitter.setPointerCapture(event.pointerId);
  updateSplitFromPointer(event.clientX, event.clientY);

  const onMove = (moveEvent) => {
    updateSplitFromPointer(moveEvent.clientX, moveEvent.clientY);
  };

  const onRelease = () => {
    paneSplitter.removeEventListener('pointermove', onMove);
    paneSplitter.removeEventListener('pointerup', onRelease);
    paneSplitter.removeEventListener('pointercancel', onRelease);
  };

  paneSplitter.addEventListener('pointermove', onMove);
  paneSplitter.addEventListener('pointerup', onRelease);
  paneSplitter.addEventListener('pointercancel', onRelease);
});

window.addEventListener('resize', applyPaneLayoutMode);

headers.forEach((header) => {
  header.addEventListener('click', () => {
    const key = header.dataset.sort;
    if (state.sortBy === key) {
      state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      state.sortBy = key;
      state.sortDir = key === 'eventTime' ? 'desc' : 'asc';
    }
    state.currentPage = 1;
    applyFilters();
  });
});

applyPaneLayoutMode();
applyControlsVisibility();
applyColumnVisibility();
reset();
setTimeMode('utc');
restoreLastFileFromStorage();
