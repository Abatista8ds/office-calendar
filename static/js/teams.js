// Estado global para equipes
let currentTeam = null;

// Adicionar funções de utilidade no início do arquivo
function showError(message) {
    // Implementar notificação de erro
    alert(message); // Temporariamente usando alert
}

function showSuccess(message) {
    // Implementar notificação de sucesso
    alert(message); // Temporariamente usando alert
}

function showModal(title, content) {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h2>${title}</h2>
                <button class="close-btn" onclick="this.closest('.modal').remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                ${content}
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    modal.style.display = 'block';
}

// Função para fechar modal
function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal && modal.style) {
        modal.style.display = 'none';
    }
}

// Função para abrir modal
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal && modal.style) {
        modal.style.display = 'block';
    }
}

// Funções do Modal
function openCreateTeamModal() {
    currentTeam = null;
    document.getElementById('modalTitle').textContent = 'Nova Equipa';
    document.getElementById('submitButtonText').textContent = 'Criar Equipa';
    document.getElementById('teamForm').reset();
    loadUsers(); // Carrega usuários para select de team lead e membros
    openModal('teamModal');
}

function openEditTeamModal(teamId) {
    currentTeam = teamId;
    document.getElementById('modalTitle').textContent = 'Editar Equipa';
    document.getElementById('submitButtonText').textContent = 'Salvar Alterações';
    loadTeamData(teamId);
    openModal('teamModal');
}

function closeTeamModal() {
    closeModal('teamModal');
    document.getElementById('teamForm').reset();
}

// Funções de API
async function loadUsers() {
    try {
        const response = await fetch('/admin/users');
        const users = await response.json();
        
        // Preencher select de team lead
        const teamLeadSelect = document.getElementById('teamLead');
        teamLeadSelect.innerHTML = '<option value="">Selecione um líder</option>';
        
        // Preencher lista de membros
        const teamMembersList = document.getElementById('teamMembers');
        teamMembersList.innerHTML = '';
        
        users.forEach(user => {
            // Adicionar opção ao select de team lead
            teamLeadSelect.innerHTML += `
                <option value="${user.email}">${user.name}</option>
            `;
            
            // Adicionar checkbox para membros
            teamMembersList.innerHTML += `
                <div class="member-item">
                    <input type="checkbox" id="member-${user.email}" 
                           name="members" value="${user.email}">
                    <label for="member-${user.email}">${user.name}</label>
                </div>
            `;
        });
    } catch (error) {
        console.error('Erro ao carregar usuários:', error);
        showError('Erro ao carregar usuários. Tente novamente.');
    }
}

async function loadTeamData(teamId) {
    try {
        const response = await fetch(`/admin/team/${teamId}`);
        const team = await response.json();
        
        document.getElementById('teamId').value = teamId;
        document.getElementById('teamName').value = team.name;
        document.getElementById('teamLead').value = team.team_lead;
        
        // Marcar membros da equipe
        team.members.forEach(memberEmail => {
            const checkbox = document.querySelector(`input[value="${memberEmail}"]`);
            if (checkbox) checkbox.checked = true;
        });
    } catch (error) {
        console.error('Erro ao carregar dados da equipe:', error);
        showError('Erro ao carregar dados da equipe. Tente novamente.');
    }
}

async function handleTeamSubmit(event) {
    event.preventDefault();
    
    try {
        const form = event.target;
        const formData = new FormData(form);
        
        // Coletar membros selecionados
        const members = Array.from(form.querySelectorAll('input[name="members"]:checked'))
            .map(input => input.value);
        
        const teamData = {
            name: formData.get('name'),
            team_lead: formData.get('team_lead'),
            mandatory_day: parseInt(formData.get('mandatory_day')),
            members: members
        };
        
        console.log('Enviando dados:', teamData);
        
        const url = currentTeam 
            ? `/admin/team/${currentTeam}/update`
            : '/admin/team/create';
            
        const response = await fetch(url, {
            method: currentTeam ? 'PUT' : 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(teamData)
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Erro ao salvar equipe');
        }
        
        closeTeamModal();
        await loadTeams();
        showSuccess(currentTeam ? 'Equipe atualizada com sucesso!' : 'Equipe criada com sucesso!');
        
    } catch (error) {
        console.error('Erro ao salvar equipe:', error);
        showError(error.message);
    }
}

// Função para carregar e exibir as equipes
async function loadTeams() {
    try {
        const response = await fetch('/admin/teams');
        const teams = await response.json();
        
        const teamsGrid = document.querySelector('.teams-grid');
        teamsGrid.innerHTML = ''; // Limpar grid atual
        
        const weekDays = {
            1: 'Segunda-feira',
            2: 'Terça-feira',
            3: 'Quarta-feira',
            4: 'Quinta-feira',
            5: 'Sexta-feira'
        };
        
        teams.forEach(team => {
            const card = `
                <div class="team-card" data-team-id="${team.id}">
                    <div class="team-header">
                        <h3 class="team-name">${team.name}</h3>
                        <div class="team-actions">
                            <button class="btn-icon" onclick="openEditTeamModal(${team.id})" title="Editar">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button class="btn-icon" onclick="viewTeamHistory(${team.id})" title="Histórico">
                                <i class="fas fa-history"></i>
                            </button>
                        </div>
                    </div>
                    
                    <div class="team-info">
                        <div class="team-mandatory-day">
                            <i class="fas fa-calendar-day"></i>
                            <span>Dia obrigatório: ${weekDays[team.mandatory_day]}</span>
                        </div>
                        <div class="team-lead-info">
                            <i class="fas fa-user-tie"></i>
                            <span>Team Lead: ${team.team_lead_name || 'Não definido'}</span>
                        </div>
                        <div class="team-members-count">
                            <i class="fas fa-users"></i>
                            <span>${team.member_count} membros</span>
                        </div>
                    </div>
                </div>
            `;
            
            teamsGrid.innerHTML += card;
        });
    } catch (error) {
        console.error('Erro ao carregar equipes:', error);
        showError('Erro ao carregar equipes. Tente novamente.');
    }
}

// Função para visualizar histórico de mudanças
async function viewTeamHistory(teamId) {
    try {
        const response = await fetch(`/admin/team/${teamId}/history`);
        const history = await response.json();
        
        const weekDays = {
            1: 'Segunda-feira',
            2: 'Terça-feira',
            3: 'Quarta-feira',
            4: 'Quinta-feira',
            5: 'Sexta-feira'
        };
        
        // Criar modal de histórico
        const historyHtml = `
            <div class="history-modal">
                <h3>Histórico de Alterações</h3>
                <div class="history-list">
                    ${history.map(entry => `
                        <div class="history-item">
                            <div class="history-date">
                                ${new Date(entry.changed_at).toLocaleDateString('pt-BR')}
                            </div>
                            <div class="history-details">
                                <span>Alterado para: ${weekDays[entry.day]}</span>
                                <span>Por: ${entry.changed_by}</span>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
        
        // Exibir modal com o histórico
        showModal('Histórico de Alterações', historyHtml);
    } catch (error) {
        console.error('Erro ao carregar histórico:', error);
        showError('Erro ao carregar histórico. Tente novamente.');
    }
}

// Carregar equipes quando a página carregar
document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelector('.teams-grid')) {
        loadTeams();
    }
});
