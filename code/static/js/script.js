// --- Resume Ranking Persistence as Cards ---
// On page load, fetch last rankings if available and display them as cards
document.addEventListener('DOMContentLoaded', function() {
    // New Ranking Button logic
    const newRankingBtn = document.getElementById('new-ranking-btn');
    if (newRankingBtn) {
        newRankingBtn.addEventListener('click', async function() {
            await fetch('/reset-session', { method: 'POST', credentials: 'same-origin' });
            // Show upload section, hide results and filter sidebar
            if (uploadSection) uploadSection.style.display = '';
            if (resultsSection) resultsSection.classList.add('hidden');
            if (filterSidebar) filterSidebar.classList.add('hidden');
            // Clear file list, results, and filters
            if (fileList) fileList.innerHTML = '';
            if (resultsContainer) resultsContainer.innerHTML = '';
            if (resultsCountSpan) resultsCountSpan.textContent = '0';
            // Optionally reset filter inputs
            if (minExpInput) minExpInput.value = '';
            if (maxExpInput) maxExpInput.value = '';
            if (minCgpaInput) minCgpaInput.value = '';
            if (educationInput) educationInput.value = '';
            if (skillsList) skillsList.innerHTML = '';
            if (selectedSkillsCount) selectedSkillsCount.textContent = '0 skills selected';
            uploadedFiles = [];
            allSkills = [];
            selectedSkills = [];
            isProcessed = false;
            // Hide the button again
            newRankingBtn.style.display = 'none';
        });
    }
    // Only run on the rank resume page (adjust selector as needed)
    const resultsSection = document.getElementById('results-section');
    const resultsContainer = document.getElementById('results-container');
    const resultsCountSpan = document.getElementById('results-count');
    const filterSidebar = document.getElementById('filter-sidebar');
    const uploadSection = document.querySelector('.upload-section');
    if (resultsContainer && resultsSection) {
        fetch('/filter-resumes', {
            method: 'GET',
            headers: {
                'Accept': 'application/json'
            },
            credentials: 'same-origin'
        })
        .then(response => response.json())
        .then(data => {
            if (data.rankings) {
                // Show the results section and render as cards
                resultsSection.classList.remove('hidden');
                resultsCountSpan.textContent = data.pagination.total_results;
                renderResultsCards(data.rankings, data.pagination);
                // Show filter sidebar and hide upload section for persistent look
                if (filterSidebar) filterSidebar.classList.remove('hidden');
                if (uploadSection) uploadSection.style.display = 'none';
                // Show the new ranking button
                if (newRankingBtn) newRankingBtn.style.display = '';
            } else {
                showNoRankingsMessage();
                if (newRankingBtn) newRankingBtn.style.display = 'none';
            }
        })
        .catch(() => {
            showNoRankingsMessage();
        });
    }
});

function renderResultsCards(rankings, pagination) {
    const resultsContainer = document.getElementById('results-container');
    if (!resultsContainer) return;
    resultsContainer.innerHTML = '';
    if (!rankings || rankings.length === 0) {
        showNoRankingsMessage();
        return;
    }
    rankings.forEach((result, index) => {
        const rank = (pagination && pagination.current_page ? (pagination.current_page - 1) * 10 : 0) + index + 1;
        const card = document.createElement('div');
        card.className = 'result-card';
        card.innerHTML = `
            <div class="rank-badge">${rank}</div>
            <div class="result-content">
                <div class="result-filename">
                    <a href="/resume/${encodeURIComponent(result.filename)}" class="candidate-link">${result.name}</a>
                </div>
                <div class="result-details">
                    <span class="detail-item"><strong>Exp:</strong> ${result.experience} yrs</span>
                    <span class="detail-item"><strong>CGPA:</strong> ${result.cgpa > 0 ? result.cgpa : 'N/A'}</span>
                    <span class="detail-item"><strong>Skills Matched:</strong> ${result.score}</span>
                </div>
            </div>
            <button class="btn btn-sm btn-outline shortlist-btn" data-filename="${result.filename}">Shortlist</button>
        `;
        resultsContainer.appendChild(card);
    });
}

function showNoRankingsMessage() {
    const resultsContainer = document.getElementById('results-container');
    if (resultsContainer) {
        resultsContainer.innerHTML = '<p>No rankings found. Please filter resumes again.</p>';
    }
}
document.addEventListener('DOMContentLoaded', () => {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    // DOM Elements
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const fileList = document.getElementById('file-list');
    const processResumesBtn = document.getElementById('process-resumes-btn');
    const filterSidebar = document.getElementById('filter-sidebar');
    const applyFilterBtn = document.getElementById('apply-filter-btn');
    
    const resultsSection = document.getElementById('results-section');
    const resultsContainer = document.getElementById('results-container');
    const resultsCountSpan = document.getElementById('results-count');

    // Filter Controls
    const skillsList = document.getElementById('skills-list');
    const skillsSearch = document.getElementById('skills-search');
    const selectAllSkillsBtn = document.getElementById('select-all-skills');
    const clearAllSkillsBtn = document.getElementById('clear-all-skills');
    const addSkillInput = document.getElementById('add-skill-input');
    const addSkillBtn = document.getElementById('add-skill-btn');
    const minExpInput = document.getElementById('min-exp');
    const maxExpInput = document.getElementById('max-exp');
    const minCgpaInput = document.getElementById('min-cgpa');
    const educationInput = document.getElementById('education-req');
    const selectedSkillsCount = document.getElementById('selected-skills-count');

    let uploadedFiles = [];
    let allSkills = [];
    let selectedSkills = [];
    let isProcessed = false;

    function setupEventListeners() {
        dropZone.addEventListener('click', () => fileInput.click());
        dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
        dropZone.addEventListener('drop', (e) => { e.preventDefault(); dropZone.classList.remove('drag-over'); handleFiles(e.dataTransfer.files); });
        fileInput.addEventListener('change', () => handleFiles(fileInput.files));
        
        processResumesBtn.addEventListener('click', processResumes);
        applyFilterBtn.addEventListener('click', applyFilters);
        
        selectAllSkillsBtn.addEventListener('click', () => updateAllSkillsSelection(true));
        clearAllSkillsBtn.addEventListener('click', () => updateAllSkillsSelection(false));
        skillsSearch.addEventListener('input', renderSkillsList);
        addSkillBtn.addEventListener('click', addNewSkill);

        resultsContainer.addEventListener('click', (e) => {
            if (e.target.classList.contains('shortlist-btn')) {
                const button = e.target;
                const filename = button.dataset.filename;
                shortlistCandidate(filename, button);
            }
        });
    }
    
    function handleFiles(files) {
        uploadedFiles = Array.from(files).filter(file => file.type === 'application/pdf');
        updateFileListUI();
        checkProcessButtonValidity();
    }

    function updateFileListUI() {
        fileList.innerHTML = uploadedFiles.map(file => `<div>${file.name}</div>`).join('');
    }

    function checkProcessButtonValidity() {
        processResumesBtn.disabled = uploadedFiles.length === 0;
    }

    async function processResumes() {
        setLoading(processResumesBtn, true);
        const formData = new FormData();
        uploadedFiles.forEach(file => formData.append('resumes', file));
        
        try {
            const response = await fetch('/process-resumes', { method: 'POST', body: formData, headers: {'X-CSRFToken': csrfToken} });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'Processing failed.');
            
            isProcessed = true;
            allSkills = data.available_skills;
            selectedSkills = [...allSkills];
            
            filterSidebar.classList.remove('hidden');
            applyFilterBtn.disabled = false;
            document.querySelector('.upload-section').style.display = 'none';
            
            renderSkillsList();
            updateSelectedCount();
            await applyFilters(); 

        } catch (error) {
            alert(`Error: ${error.message}`);
        } finally {
            setLoading(processResumesBtn, false);
        }
    }

    async function applyFilters() {
        if (!isProcessed) return;
        setLoading(applyFilterBtn, true);

        const filterData = {
            selected_skills: selectedSkills,
            min_exp: minExpInput.value || 0,
            max_exp: maxExpInput.value || 100,
            min_cgpa: minCgpaInput.value || 0,
            education_req: educationInput.value || ''
        };

        try {
            const response = await fetch('/filter-resumes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify(filterData)
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'Filtering failed.');
            
            displayResults(data.rankings, data.pagination);

        } catch (error) {
            alert(`Error: ${error.message}`);
        } finally {
            setLoading(applyFilterBtn, false);
        }
    }

    function displayResults(rankings, pagination) {
        resultsSection.classList.remove('hidden');
        resultsCountSpan.textContent = pagination.total_results;
        resultsContainer.innerHTML = '';
        
    if (rankings.length === 0) {
        resultsContainer.innerHTML = '<p>No resumes match the current filters.</p>';
    } else {
        // Show the Start New Ranking button after displaying results
        const newRankingBtn = document.getElementById('new-ranking-btn');
        if (newRankingBtn) newRankingBtn.style.display = '';
        rankings.forEach((result, index) => {
            const rank = (pagination.current_page - 1) * 10 + index + 1;
            const card = document.createElement('div');
            card.className = 'result-card';
            card.innerHTML = `
                <div class="rank-badge">${rank}</div>
                <div class="result-content">
                    <div class="result-filename">
                        <a href="/resume/${encodeURIComponent(result.filename)}" class="candidate-link">${result.name}</a>
                    </div>
                    <div class="result-details">
                        <span class="detail-item"><strong>Exp:</strong> ${result.experience} yrs</span>
                        <span class="detail-item"><strong>Education:</strong> ${result.education}</span>
                        <span class="detail-item"><strong>CGPA:</strong> ${result.cgpa > 0 ? result.cgpa : 'N/A'}</span>
                        <span class="detail-item"><strong>Skills Matched:</strong> ${result.score}</span>
                    </div>
                </div>
                <button class="btn btn-sm btn-outline shortlist-btn" data-filename="${result.filename}">Shortlist</button>
            `;
                resultsContainer.appendChild(card);
            });
        }
    }
    
    function renderSkillsList() {
        const searchTerm = skillsSearch.value.toLowerCase();
        const filtered = allSkills.filter(s => s.toLowerCase().includes(searchTerm));
        const skillItems = filtered.map(skill => `
            <div class="skill-item">
                <label><input type="checkbox" class="skill-checkbox" value="${skill}" ${selectedSkills.includes(skill) ? 'checked' : ''}><span>${skill}</span></label>
            </div>`).join('');
        skillsList.innerHTML = skillItems;
        attachSkillCheckboxListeners();
    }

    function attachSkillCheckboxListeners() {
        skillsList.querySelectorAll('.skill-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const skill = e.target.value;
                if (e.target.checked) {
                    if (!selectedSkills.includes(skill)) selectedSkills.push(skill);
                } else {
                    selectedSkills = selectedSkills.filter(s => s !== skill);
                }
                updateSelectedCount();
            });
        });
    }

    function updateAllSkillsSelection(shouldSelect) {
        const searchTerm = skillsSearch.value.toLowerCase();
        const filtered = allSkills.filter(s => s.toLowerCase().includes(searchTerm));
        if (shouldSelect) {
            filtered.forEach(skill => { if (!selectedSkills.includes(skill)) selectedSkills.push(skill); });
        } else {
            selectedSkills = selectedSkills.filter(s => !filtered.includes(s));
        }
        renderSkillsList();
        updateSelectedCount();
    }

    function addNewSkill() {
        const newSkill = addSkillInput.value.trim().toLowerCase();
        if (!newSkill) return;
        if (!allSkills.map(s => s.toLowerCase()).includes(newSkill)) {
            allSkills.push(newSkill);
            allSkills.sort();
            if (!selectedSkills.includes(newSkill)) {
                selectedSkills.push(newSkill);
            }
            renderSkillsList();
            updateSelectedCount();
        }
        addSkillInput.value = '';
    }

    function updateSelectedCount() {
        selectedSkillsCount.textContent = `${selectedSkills.length} of ${allSkills.length} skills selected`;
    }
    
    async function shortlistCandidate(filename, button) {
        button.disabled = true;
        button.textContent = '...';
        try {
            const response = await fetch('/shortlist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify({ filename: filename })
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error);
            button.textContent = data.status === 'exists' ? '✓ Exists' : '✓ Shortlisted';
            button.classList.add('shortlisted');
        } catch (error) {
            alert(`Error: ${error.message}`);
            button.disabled = false;
            button.textContent = 'Shortlist';
        }
    }

    function setLoading(button, isLoading) {
        const text = button.querySelector('.btn-text');
        const spinner = button.querySelector('.spinner');
        button.disabled = isLoading;
        if(text) text.style.display = isLoading ? 'none' : 'inline';
        if(spinner) spinner.style.display = isLoading ? 'block' : 'none';
    }

    setupEventListeners();
});