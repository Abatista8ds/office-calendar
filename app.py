from flask import Flask, render_template, request, redirect, session, current_app, jsonify, g
from firebase_admin import credentials, auth, initialize_app
import os
from dotenv import load_dotenv
from google.oauth2 import id_token
from google.auth.transport import requests
from datetime import datetime, timedelta
from google.cloud import datastore
from functools import wraps, lru_cache
import calendar
import json
from collections import defaultdict
from calendar import month_name
import threading
from dateutil.relativedelta import relativedelta

# Adicionar no início do arquivo, junto com as outras importações
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Não autorizado'}), 401
        if session['user']['email'] not in get_admin_emails():
            return jsonify({'error': 'Acesso restrito a administradores'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Definir o dicionário meses no escopo global
meses = {
    1: 'Janeiro',
    2: 'Fevereiro',
    3: 'Março',
    4: 'Abril',
    5: 'Maio',
    6: 'Junho',
    7: 'Julho',
    8: 'Agosto',
    9: 'Setembro',
    10: 'Outubro',
    11: 'Novembro',
    12: 'Dezembro'
}

# Carregar variáveis de ambiente ANTES de qualquer verificação
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key')
app.debug = True  # Ativa o modo debug

# Verificar e configurar o Firebase
cred_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
if not cred_path or not os.path.exists(cred_path):
    raise ValueError(
        f"Arquivo de credenciais não encontrado em: {cred_path}\n"
        "Verifique se o caminho está correto no arquivo .env"
    )

try:
    cred = credentials.Certificate(cred_path)
    initialize_app(cred)
    client = datastore.Client()
except Exception as e:
    print(f"Erro ao inicializar Firebase: {e}")
    raise

# Criar contexto da aplicação para listar templates
with app.app_context():
    print("Templates disponíveis:", current_app.jinja_loader.list_templates())

# Lista de emails de administradores
ADMIN_EMAILS = ['andre.batista@wisepirates.com']

# Cache com estrutura otimizada
class ReservationCache:
    def __init__(self, timeout=300):
        self.cache = {}
        self.lock = threading.Lock()
        self.timeout = timeout

    def get(self, key):
        with self.lock:
            if key in self.cache:
                data, timestamp = self.cache[key]
                if timestamp > datetime.now() - timedelta(seconds=self.timeout):
                    return data
                del self.cache[key]
            return None

    def set(self, key, data):
        with self.lock:
            self.cache[key] = (data, datetime.now())

# Instanciar cache global
reservation_cache = ReservationCache()

def get_month_reservations(year, month):
    """Busca todas as reservas do mês de uma vez"""
    cache_key = f"month:{year}:{month}"
    
    # Tentar pegar do cache primeiro
    cached_data = reservation_cache.get(cache_key)
    if cached_data:
        return cached_data
    
    # Query única para o mês todo
    start_date = f"{year}-{month:02d}-01"
    end_date = f"{year}-{month:02d}-31"
    
    query = client.query(kind='Reservation')
    query.add_filter('status', '=', 'active')
    
    # Organizar dados em estrutura otimizada
    reservations_by_date = defaultdict(list)
    user_reservations = defaultdict(list)
    
    for reservation in query.fetch():
        date = reservation.get('date', '')
        if start_date <= date <= end_date:
            reservations_by_date[date].append(reservation)
            user_reservations[reservation['user']].append(reservation)
    
    result = {
        'by_date': dict(reservations_by_date),
        'by_user': dict(user_reservations)
    }
    
    # Guardar no cache
    reservation_cache.set(cache_key, result)
    return result

@app.route('/')
def index():
    if 'user' not in session:
        return redirect('/login')
    
    today = datetime.now()
    
    # Buscar todas as reservas (não só do usuário)
    query = client.query(kind='Reservation')
    query.add_filter('status', '=', 'active')
    all_reservations = list(query.fetch())
    
    # Filtrar reservas do usuário atual para este mês
    current_month = today.strftime('%Y-%m')
    user_month_reservations = [
        r for r in all_reservations 
        if r.get('user') == session['user']['email'] 
        and r.get('date', '').startswith(current_month)
    ]
    
    # Contar dias únicos do usuário neste mês
    user_days = len(set(r.get('date') for r in user_month_reservations))
    
    # Agrupar reservas por data para verificar dias lotados
    reservations_by_date = {}
    for r in all_reservations:
        date = r.get('date')
        if date:
            if date not in reservations_by_date:
                reservations_by_date[date] = []
            reservations_by_date[date].append(r)
    
    # Preparar dados do calendário
    calendar_data = []
    year = today.year
    month = today.month
    _, days_in_month = calendar.monthrange(year, month)
    
    for day in range(1, days_in_month + 1):
        date = f"{year}-{month:02d}-{day:02d}"
        weekday = datetime.strptime(date, '%Y-%m-%d').weekday()
        
        # Verificar se é fim de semana
        is_weekend = weekday >= 5
        
        # Verificar se o dia está lotado
        day_reservations = reservations_by_date.get(date, [])
        is_full = len(day_reservations) >= 3
        
        # Verificar se o usuário tem reserva neste dia
        user_reservation = next(
            (r for r in day_reservations if r['user'] == session['user']['email']),
            None
        )
        
        calendar_data.append({
            'day': day,
            'date': date,
            'is_weekend': is_weekend,
            'is_full': is_full,
            'reserved': bool(user_reservation),
            'class': 'weekend' if is_weekend else 'day-full' if is_full else 'reserved' if user_reservation else ''
        })
    
    # Buscar lista de admins
    admin_emails = get_admin_emails()
    
    return render_template('index.html',
                         user=session['user'],
                         email=session['user']['email'],
                         days_this_month=f"{user_days}/10 dias este mês",
                         is_admin=is_admin(session['user']['email']),
                         admin_emails=admin_emails,
                         required_days=10,
                         calendar_data=calendar_data)

@app.route('/login', methods=['GET', 'POST'])
def login():
    print("Acessando rota /login")  # Debug print
    try:
        if request.method == 'POST':
            print("Método POST recebido")  # Debug print
            email = request.form['email']
            password = request.form['password']
            
            try:
                user = auth.get_user_by_email(email)
                session['user'] = {
                    'email': user.email,
                    'uid': user.uid
                }
                return redirect('/')
            except Exception as e:
                print(f"Erro no login: {e}")  # Debug print
                return render_template('login.html', message="Login falhou: " + str(e))
        
        print("Renderizando template login.html")  # Debug print
        return render_template('login.html')
    except Exception as e:
        print(f"Erro na rota login: {e}")  # Debug print
        return str(e), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    print("Acessando rota /register")  # Debug print
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        try:
            user = auth.create_user(email=email, password=password)
            return redirect('/login')
        except Exception as e:
            print(f"Erro no registro: {e}")  # Debug print
            return "Registro falhou"
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

@app.route('/google-login', methods=['POST'])
def google_login():
    try:
        # Recebe o token ID do cliente
        token = request.json['token']
        
        # Verifica o token usando Firebase Admin
        decoded_token = auth.verify_id_token(token)
        
        # Pega o email do token decodificado
        email = decoded_token['email']
        
        # Cria ou obtém o usuário
        try:
            user = auth.get_user_by_email(email)
        except:
            user = auth.create_user(
                email=email,
                email_verified=True
            )
        
        # Cria a sessão
        session['user'] = {
            'email': user.email,
            'uid': user.uid
        }
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Erro no login com Google: {e}")
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/make-reservation', methods=['POST'])
def make_reservation():
    if 'user' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
    
    data = request.get_json()
    date = data.get('date')
    res_type = data.get('type', 'full')
    
    # Invalidar cache ao fazer reserva
    year, month = date.split('-')[:2]
    cache_key = f"month:{year}:{month}"
    reservation_cache.cache.pop(cache_key, None)
    
    # Se for cancelamento, processa de forma diferente
    currently_reserved = data.get('currentlyReserved', False)
    if currently_reserved:
        query = client.query(kind='Reservation')
        query.add_filter('date', '=', date)
        query.add_filter('user', '=', session['user']['email'])
        query.add_filter('status', '=', 'active')
        reservation = list(query.fetch(limit=1))
        
        if not reservation:
            return jsonify({'error': 'Reserva não encontrada'}), 404

        # Permite admin cancelar qualquer reserva ou usuário cancelar própria reserva
        if session['user']['email'] in ADMIN_EMAILS or reservation[0]['user'] == session['user']['email']:
            reservation[0].update({
                'status': 'cancelled',
                'cancelled_at': datetime.now()
            })
            client.put(reservation[0])
            return jsonify({'success': True})
        return jsonify({'error': 'Não autorizado a cancelar esta reserva'}), 403
        
    # Se não for cancelamento, continua com a lógica de criar reserva
    
    # Verificar se já existe reserva para este dia
    query = client.query(kind='Reservation')
    query.add_filter('date', '=', date)
    query.add_filter('status', '=', 'active')
    existing_reservations = list(query.fetch())
    
    # Verificar limite de 3 pessoas por dia
    if len(existing_reservations) >= 3:
        return jsonify({'error': 'Dia lotado'}), 400
        
    # Verificar se usuário já tem reserva neste dia
    user_reservation = next(
        (r for r in existing_reservations if r['user'] == session['user']['email']),
        None
    )
    
    if user_reservation:
        return jsonify({'error': 'Você já tem uma reserva neste dia'}), 400
        
    # Criar nova reserva
    reservation = datastore.Entity(client.key('Reservation'))
    reservation.update({
        'user': session['user']['email'],
        'date': date,
        'type': res_type,
        'status': 'active',
        'created_at': datetime.now()
    })
    client.put(reservation)
    
    return jsonify({'success': True})

@app.route('/cancel_reservation/<reservation_id>', methods=['POST'])
def cancel_reservation(reservation_id):
    try:
        if 'user' not in session:
            return jsonify({'error': 'Não autorizado'}), 401
            
        key = client.key('Reservation', int(reservation_id))
        reservation = client.get(key)
        
        if not reservation:
            return jsonify({'error': 'Reserva não encontrada'}), 404
            
        if reservation['user'] != session['user']['email']:
            return jsonify({'error': 'Não autorizado'}), 401
            
        reservation['status'] = 'cancelled'
        client.put(reservation)
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Erro ao cancelar reserva: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        period = request.args.get('period', 'current')
        today = datetime.now()
        
        # Determinar o período baseado no parâmetro
        if period == 'previous':
            start_date = (today.replace(day=1) - relativedelta(months=1))
            period_title = (today - relativedelta(months=1)).strftime('%B %Y')
        elif period == 'next':
            start_date = (today.replace(day=1) + relativedelta(months=1))
            period_title = (today + relativedelta(months=1)).strftime('%B %Y')
        elif period == 'annual':
            start_date = today.replace(month=1, day=1)
            period_title = f"Ano {today.year}"
        else:  # current
            start_date = today.replace(day=1)
            period_title = today.strftime('%B %Y')
            
        # Ajustar data final
        if period == 'annual':
            end_date = start_date.replace(month=12, day=31)
        else:
            next_month = start_date + relativedelta(months=1)
            end_date = next_month - relativedelta(days=1)
        
        # Buscar usuários
        user_query = client.query(kind='User')
        users = list(user_query.fetch())
        
        # Buscar reservas do período
        query = client.query(kind='Reservation')
        query.add_filter('date', '>=', start_date.strftime('%Y-%m-%d'))
        query.add_filter('date', '<=', end_date.strftime('%Y-%m-%d'))
        query.add_filter('status', '=', 'active')
        reservations = list(query.fetch())
        
        # Calcular dias por usuário considerando meio dia
        user_days = defaultdict(float)  # Mudado para float para suportar 0.5
        for res in reservations:
            user_days[res['user']] += 1.0 if res.get('type') == 'full' else 0.5
        
        # Preparar dados para a tabela
        users_data = []
        for user in users:
            email = user.get('email')
            days = user_days.get(email, 0.0)  # Pegar valor float
            
            # Calcular progresso
            progress = (days / 10.0) * 100 if period != 'annual' else 0
            
            users_data.append({
                'name': user.get('name', 'Sem nome'),
                'email': email,
                'team': user.get('team', 'Sem equipe'),
                'days_in_period': days,  # Já é float
                'progress': min(progress, 100)  # Limitar a 100%
            })
        
        # Ordenar por dias (decrescente) e nome (crescente)
        users_data.sort(key=lambda x: (-x['days_in_period'], x['name']))
        
        # Adicionar estatísticas básicas
        stats = {
            'total_users': len(users),
            'total_reservations': len(reservations),
            'average_days': sum(user_days.values()) / len(users) if users else 0
        }
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'users': users_data,
                'period_title': period_title,
                'stats': stats
            })
            
        return render_template('admin_dashboard.html',
                             users=users_data,
                             current_period=period,
                             period_title=period_title,
                             stats=stats)
                             
    except Exception as e:
        print(f"Erro no dashboard: {str(e)}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': str(e)}), 500
        return f"Erro: {str(e)}", 500

@app.route('/admin/update_requirements', methods=['POST'])
@admin_required
def update_requirements():
    try:
        email = request.form['email']
        required_days = int(request.form['required_days'])
        role = request.form['role']
        
        # Buscar ou criar requisitos do usuário
        query = client.query(kind='UserRequirements')
        query.add_filter('email', '=', email)
        results = list(query.fetch(limit=1))
        
        if results:
            entity = results[0]
            entity.update({
                'required_days': required_days,
                'role': role
            })
        else:
            key = client.key('UserRequirements')
            entity = datastore.Entity(key=key)
            entity.update({
                'email': email,
                'required_days': required_days,
                'role': role
            })
        
        client.put(entity)
        return redirect('/admin')
        
    except Exception as e:
        print(f"Erro ao atualizar requisitos: {e}")
        return str(e), 500

@app.route('/admin/cancel_reservation/<reservation_id>', methods=['POST'])
@admin_required
def admin_cancel_reservation(reservation_id):
    try:
        key = client.key('Reservation', int(reservation_id))
        reservation = client.get(key)
        
        if not reservation:
            return "Reserva não encontrada", 404
            
        reservation['status'] = 'cancelled'
        reservation['cancelled_at'] = datetime.now()
        reservation['cancelled_by'] = session['user']['email']
        
        client.put(reservation)
        return "", 204
        
    except Exception as e:
        print(f"Erro ao cancelar reserva: {e}")
        return str(e), 500

# Adicione esta rota temporária para criar o admin
@app.route('/setup_admin/<email>')
def setup_admin(email):
    try:
        create_admin(email)
        return f"Admin {email} criado com sucesso!"
    except Exception as e:
        return f"Erro ao criar admin: {e}", 500

def create_admin(email):
    key = client.key('UserRequirements')
    entity = datastore.Entity(key=key)
    entity.update({
        'email': email,
        'required_days': 0,  # Admin não precisa de dias mínimos
        'role': 'admin'
    })
    client.put(entity)

@app.route('/calendar-data')
def get_calendar_data():
    try:
        month = request.args.get('month', datetime.now().strftime('%Y-%m'))
        year, month = map(int, month.split('-'))
        last_day = calendar.monthrange(year, int(month))[1]
        
        # Buscar todas as reservas do mês
        query = client.query(kind='Reservation')
        query.add_filter('date', '>=', f"{year}-{month:02d}-01")
        query.add_filter('date', '<=', f"{year}-{month:02d}-{last_day:02d}")
        query.add_filter('status', '=', 'active')
        month_reservations = list(query.fetch())
        
        calendar_data = {}
        for day in range(1, last_day + 1):
            date_str = f"{year}-{month:02d}-{day:02d}"
            
            # Buscar reservas para este dia
            day_reservations = [r for r in month_reservations if r['date'] == date_str]
            
            # Calcular contagem total (full = 1, half = 0.5)
            count = sum(1.0 if r.get('type') == 'full' else 0.5 for r in day_reservations)
            
            # Verificar se o usuário atual tem reserva neste dia
            user_reservation = next(
                (r for r in day_reservations if r['user'] == session.get('user')['email']), 
                None
            )
            
            print(f"Data: {date_str}, Count: {count}, Reservas: {len(day_reservations)}") # Debug
            
            calendar_data[date_str] = {
                'reserved': bool(user_reservation),
                'type': user_reservation.get('type') if user_reservation else None,
                'count': count,
                'total_reservations': len(day_reservations)  # Adicional para debug
            }
            
        return jsonify(calendar_data)
    except Exception as e:
        print(f"Erro: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/availability/<date>')
def check_availability(date):
    if 'user' not in session:
        return redirect('/login')
        
    # Buscar todas as reservas para a data
    query = client.query(kind='Reservation')
    query.add_filter('date', '=', date)
    query.add_filter('status', '=', 'active')
    
    reservations = list(query.fetch())
    
    # Lista de todas as mesas/espaços
    all_desks = [
        {'id': 'desk1', 'name': 'Mesa 1', 'capacity': 1},
        {'id': 'desk2', 'name': 'Mesa 2', 'capacity': 1},
        {'id': 'meeting', 'name': 'Sala de Reunião', 'capacity': 8}
    ]
    
    # Calcular disponibilidade
    reserved_desks = {r['desk'] for r in reservations}
    available_desks = [
        {
            'id': desk['id'],
            'name': desk['name'],
            'available': 'Ocupado' if desk['id'] in reserved_desks else 'Livre'
        }
        for desk in all_desks
    ]
    
    return jsonify({'desks': available_desks})

@app.route('/admin/reservations')
def admin_reservations():
    try:
        if 'user' not in session:
            return redirect('/login')
            
        # Verificar se é admin
        if session['user']['email'] not in ['seu.email@wisepirates.com']:
            return "Não autorizado", 401
            
        # Buscar todas as reservas
        query = client.query(kind='Reservation')
        reservations = list(query.fetch())
        
        # Organizar dados
        formatted_reservations = []
        for res in reservations:
            formatted_reservations.append({
                'id': res.key.id,
                'date': res['date'],
                'user': res['user'],
                'type': res.get('type', 'full'),
                'status': res.get('status', 'active'),
                'created_at': res.get('created_at', '').strftime('%Y-%m-%d %H:%M:%S')
            })
            
        return render_template('admin_reservations.html', 
                             reservations=formatted_reservations)
                             
    except Exception as e:
        print(f"Erro ao buscar reservas: {e}")
        return str(e), 500

# Lista de admins agora será armazenada no Datastore
def get_admin_emails():
    query = client.query(kind='Admin')
    admins = list(query.fetch())
    return [admin['email'] for admin in admins]

def is_admin(email):
    return email in get_admin_emails()

@app.route('/admin/list')
def list_admins():
    try:
        if 'user' not in session or not is_admin(session['user']['email']):
            return jsonify({'error': 'Não autorizado'}), 401
            
        return jsonify({'admins': get_admin_emails()})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/add', methods=['POST'])
def add_admin():
    try:
        if 'user' not in session or not is_admin(session['user']['email']):
            return jsonify({'error': 'Não autorizado'}), 401
            
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email não fornecido'}), 400
            
        # Verificar se já é admin
        if is_admin(email):
            return jsonify({'error': 'Email já é admin'}), 400
            
        # Adicionar novo admin
        admin = datastore.Entity(client.key('Admin'))
        admin.update({
            'email': email,
            'added_by': session['user']['email'],
            'added_at': datetime.now()
        })
        client.put(admin)
        
        # Limpar cache
        if hasattr(g, 'admin_emails'):
            delattr(g, 'admin_emails')
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/delete', methods=['POST'])
def delete_admin():
    try:
        if 'user' not in session or not is_admin(session['user']['email']):
            return jsonify({'error': 'Não autorizado'}), 401
            
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email não fornecido'}), 400
            
        # Não permitir remover o último admin
        admins = get_admin_emails()
        if len(admins) <= 1:
            return jsonify({'error': 'Não é possível remover o último administrador'}), 400
            
        # Remover admin
        query = client.query(kind='Admin')
        query.add_filter('email', '=', email)
        admin = list(query.fetch())
        
        if admin:
            client.delete(admin[0].key)
            
        # Limpar cache
        if hasattr(g, 'admin_emails'):
            delattr(g, 'admin_emails')
            
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Função para inicializar o primeiro admin
def initialize_admin():
    query = client.query(kind='Admin')
    admins = list(query.fetch())
    
    # Se não houver admins, criar o primeiro
    if not admins:
        first_admin = datastore.Entity(client.key('Admin'))
        first_admin.update({
            'email': 'andre.batista@wisepirates.com',
            'added_at': datetime.now(),
            'is_initial': True
        })
        client.put(first_admin)
        print("Primeiro admin inicializado!")

# Chamar a função quando a aplicação iniciar
initialize_admin()

@app.before_request
def load_admin_cache():
    if not hasattr(g, 'admin_emails'):
        g.admin_emails = get_admin_emails()

def is_admin(email):
    return email in getattr(g, 'admin_emails', get_admin_emails())

def check_day_availability(date):
    """Verifica se ainda há vagas para o dia"""
    query = client.query(kind='Reservation')
    query.add_filter('date', '=', date)
    query.add_filter('status', '=', 'active')
    reservations = list(query.fetch())
    return len(reservations) < 3, len(reservations)  # Retorna disponibilidade e total de reservas

@app.route('/admin/month-detail')
def month_detail():
    if 'user' not in session or session['user']['email'] not in get_admin_emails():
        return jsonify({'error': 'Não autorizado'}), 401

    email = request.args.get('email')
    month_key = request.args.get('month')
    
    if not email or not month_key:
        return jsonify({'error': 'Parâmetros inválidos'}), 400

    year, month = map(int, month_key.split('-'))
    
    # Buscar reservas do usuário no mês
    query = client.query(kind='Reservation')
    query.add_filter('user', '=', email)
    query.add_filter('status', '=', 'active')
    reservations = list(query.fetch())
    
    # Filtrar reservas do mês específico
    month_reservations = [
        r for r in reservations 
        if r['date'].startswith(f"{year}-{month:02d}")
    ]
    
    # Calcular dias do mês
    _, days_in_month = calendar.monthrange(year, month)
    calendar_days = []
    
    for day in range(1, days_in_month + 1):
        date = f"{year}-{month:02d}-{day:02d}"
        weekday = datetime.strptime(date, '%Y-%m-%d').weekday()
        is_weekend = weekday >= 5
        
        # Verificar disponibilidade e total de reservas
        is_available, total_reservations = check_day_availability(date)
        is_full = total_reservations >= 3
        
        reservation = next(
            (r for r in month_reservations if r['date'] == date),
            None
        )
        
        # Definir classe CSS apropriada
        if is_weekend:
            day_class = 'weekend'
        elif is_full:
            day_class = 'day-full'  # Nova classe para dias lotados
        elif reservation:
            day_class = 'reserved'
        else:
            day_class = ''
        
        calendar_days.append({
            'day': day,
            'date': date,
            'reserved': bool(reservation),
            'type': reservation.get('type', '') if reservation else '',
            'class': day_class,
            'total_reservations': total_reservations
        })
    
    # Para cada dia, verificar se está lotado
    for day in calendar_days:
        date = day['date']
        query = client.query(kind='Reservation')
        query.add_filter('date', '=', date)
        query.add_filter('status', '=', 'active')
        all_reservations = list(query.fetch())
        
        day['is_full'] = len(all_reservations) >= 3
        day['reserved'] = any(r['user'] == email for r in all_reservations)

    month_name = f"{meses[month]} {year}"
    
    return jsonify({
        'month_name': month_name,
        'days': calendar_days
    })

@app.route('/admin/toggle-reservation', methods=['POST'])
def admin_toggle_reservation():
    if 'user' not in session or session['user']['email'] not in get_admin_emails():
        return jsonify({'error': 'Não autorizado'}), 401

    data = request.get_json()
    email = data.get('email')
    date = data.get('date')
    currently_reserved = data.get('currentlyReserved', False)
    res_type = data.get('type', 'full')
    force_add = data.get('force_add', False)  # Novo parâmetro para forçar adição

    # Verificar reservas existentes
    query = client.query(kind='Reservation')
    query.add_filter('date', '=', date)
    query.add_filter('status', '=', 'active')
    existing_reservations = list(query.fetch())

    # Se for cancelamento
    if currently_reserved:
        user_reservation = next(
            (r for r in existing_reservations if r['user'] == email),
            None
        )
        if user_reservation:
            user_reservation.update({
                'status': 'cancelled',
                'cancelled_at': datetime.now()
            })
            client.put(user_reservation)
            return jsonify({'success': True})
        return jsonify({'error': 'Reserva não encontrada'}), 404

    # Se for nova reserva
    # Verificar lotação e avisar admin
    if len(existing_reservations) >= 3 and not force_add:
        return jsonify({
            'warning': f'Dia já tem {len(existing_reservations)} reservas. Deseja adicionar mais uma?',
            'needsConfirmation': True
        })

    # Criar nova reserva
    reservation = datastore.Entity(client.key('Reservation'))
    reservation.update({
        'user': email,
        'date': date,
        'type': res_type,
        'status': 'active',
        'created_at': datetime.now(),
        'created_by': session['user']['email']
    })
    client.put(reservation)
    
    return jsonify({'success': True})

def calculate_stats(period='current'):
    try:
        today = datetime.now()
        
        # Determinar período
        if period == 'current':
            start_date = today.replace(day=1)
            _, last_day = calendar.monthrange(today.year, today.month)
            end_date = today.replace(day=last_day)
            period_name = f"{meses[today.month]} {today.year}"
        elif period == 'previous':
            if today.month == 1:
                start_date = today.replace(year=today.year-1, month=1, day=1)
                end_date = start_date.replace(day=31)
            else:
                start_date = today.replace(month=today.month-1, day=1)
                _, last_day = calendar.monthrange(today.year, today.month-1)
                end_date = start_date.replace(day=last_day)
            period_name = f"{meses[start_date.month]} {start_date.year}"
        elif period == 'next':
            if today.month == 12:
                start_date = today.replace(year=today.year+1, month=1, day=1)
                end_date = start_date.replace(day=31)
            else:
                start_date = today.replace(month=today.month+1, day=1)
                _, last_day = calendar.monthrange(today.year, today.month+1)
                end_date = start_date.replace(day=last_day)
            period_name = f"{meses[start_date.month]} {start_date.year}"
        else:  # year
            start_date = today.replace(month=1, day=1)
            end_date = today.replace(month=12, day=31)
            period_name = f"Ano {today.year}"

        # Buscar todas as reservas
        query = client.query(kind='Reservation')
        query.add_filter('status', '=', 'active')
        reservations = list(query.fetch())
        
        # Filtrar reservas do período e contar por usuário
        users = set(r['user'] for r in reservations)
        user_days = {}
        
        for user in users:
            days = count_user_days(reservations, user, start_date, end_date)
            if days > 0:  # Só incluir usuários com reservas no período
                user_days[user] = days
        
        total_users = len(user_days)
        total_reservations = sum(user_days.values())
        
        # Calcular ocupação
        working_days = sum(1 for date in (start_date + timedelta(n) 
                          for n in range((end_date - start_date).days + 1))
                          if date.weekday() < 5)
        
        avg_occupation = round(
            (total_reservations / (working_days * max(total_users, 1))) * 100, 1
        ) if working_days and total_users else 0
        
        # Calcular meta atingida
        required_days = 120 if period == 'year' else 10
        users_reached_goal = sum(1 for days in user_days.values() if days >= required_days)
        
        goal_reached = round(
            (users_reached_goal / max(total_users, 1)) * 100, 1
        ) if total_users else 0
        
        print(f"Debug - Stats para período {period}:")
        print(f"Users: {total_users}")
        print(f"Reservations: {total_reservations}")
        print(f"User days: {user_days}")
        
        return {
            'total_users': total_users,
            'total_reservations': total_reservations,
            'avg_occupation': avg_occupation,
            'goal_reached': goal_reached,
            'period_name': period_name
        }
        
    except Exception as e:
        print(f"Erro ao calcular estatísticas: {e}")
        return {
            'total_users': 0,
            'total_reservations': 0,
            'avg_occupation': 0,
            'goal_reached': 0,
            'period_name': 'Erro'
        }

# Nova rota para atualização das stats via AJAX
@app.route('/admin/stats')
@admin_required
def admin_stats():
    try:
        period = request.args.get('period', 'current')
        
        # Definir período
        today = datetime.now()
        
        if period == 'current':
            start_date = today.replace(day=1)
            end_date = (start_date + relativedelta(months=1, days=-1))
            period_name = f"{start_date.strftime('%B %Y')}"
            
        elif period == 'previous':
            start_date = (today + relativedelta(months=-1)).replace(day=1)
            end_date = (start_date + relativedelta(months=1, days=-1))
            period_name = f"{start_date.strftime('%B %Y')}"
            
        elif period == 'next':
            start_date = (today + relativedelta(months=1)).replace(day=1)
            end_date = (start_date + relativedelta(months=1, days=-1))
            period_name = f"{start_date.strftime('%B %Y')}"
            
        elif period == 'year':
            start_date = today.replace(month=1, day=1)
            end_date = today.replace(month=12, day=31)
            period_name = f"Ano {today.year}"
            
        else:
            return jsonify({'error': 'Período inválido'})

        # Buscar todas as reservas do período
        query = client.query(kind='Reservation')
        query.add_filter('date', '>=', start_date.strftime('%Y-%m-%d'))
        query.add_filter('date', '<=', end_date.strftime('%Y-%m-%d'))
        query.add_filter('status', '=', 'active')
        reservations = list(query.fetch())

        # Calcular estatísticas
        total_users = len(set(r['user'] for r in reservations))
        
        # Calcular ocupação média
        business_days = sum(1 for date in (start_date + timedelta(n) for n in range((end_date - start_date).days + 1))
                          if date.weekday() < 5)
        total_spots = business_days * 3  # 3 vagas por dia
        total_reservations = sum(1 if r['type'] == 'full' else 0.5 for r in reservations)
        avg_occupation = round((total_reservations / total_spots) * 100) if total_spots > 0 else 0

        # Calcular meta atingida (10 dias por mês ou 120 dias por ano)
        users_with_days = {}
        for res in reservations:
            if res['user'] not in users_with_days:
                users_with_days[res['user']] = 0
            users_with_days[res['user']] += 1 if res['type'] == 'full' else 0.5

        # Meta diferente para ano (120 dias) e mês (10 dias)
        required_days = 120 if period == 'year' else 10
        users_reached_goal = sum(1 for days in users_with_days.values() if days >= required_days)
        goal_reached = round(users_reached_goal / total_users * 100) if total_users > 0 else 0

        return jsonify({
            'total_users': total_users,
            'avg_occupation': avg_occupation,
            'total_reservations': total_reservations,
            'goal_reached': goal_reached,
            'period_name': period_name
        })

    except Exception as e:
        print(f"Erro ao calcular estatísticas: {str(e)}")
        return jsonify({'error': str(e)})

@app.route('/month-data')
def month_data():
    if 'user' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
        
    year = int(request.args.get('year'))
    month = int(request.args.get('month'))
    email = session['user']['email']
    
    # Query simplificada usando índices existentes
    query = client.query(kind='Reservation')
    query.add_filter('status', '=', 'active')
    
    all_reservations = list(query.fetch())
    
    # Filtrar por mês em memória
    start_date = f"{year}-{month:02d}-01"
    end_date = f"{year}-{month:02d}-31"
    month_reservations = [
        res for res in all_reservations 
        if start_date <= res['date'] <= end_date
    ]
    
    # Processar reservas por data
    reservations_by_date = {}
    for res in month_reservations:
        date = res.get('date')
        if date not in reservations_by_date:
            reservations_by_date[date] = []
        reservations_by_date[date].append(res)
    
    # Preparar dados do calendário
    calendar_data = []
    for date, reservations in reservations_by_date.items():
        is_mine = any(r['user'] == email for r in reservations)
        is_full = len(reservations) >= 3
        
        if is_mine or is_full:
            my_reservation = next((r for r in reservations if r['user'] == email), None)
            calendar_data.append({
                'date': date,
                'is_mine': is_mine,
                'is_full': is_full,
                'type': my_reservation['type'] if my_reservation else None
            })
    
    # Calcular total de dias do mês
    month_days = sum(
        1 if r['user'] == email and r.get('type') == 'full' else 0.5 
        for r in month_reservations 
        if r['user'] == email
    )
    
    # Adicionar informação de meta atingida
    for data in calendar_data:
        if data['is_mine']:
            data['goal_reached'] = month_days >= 10
    
    return jsonify(calendar_data)

@app.route('/office-state/<date>')
def get_office_state(date):
    try:
        # Buscar todas as reservas para a data
        query = client.query(kind='Reservation')
        query.add_filter('date', '=', date)
        query.add_filter('status', '=', 'active')
        reservations = list(query.fetch())
        
        # Calcular ocupação total (full day = 1, half day = 0.5)
        total_count = sum(1.0 if r.get('type') == 'full' else 0.5 for r in reservations)
        
        return jsonify({
            'count': total_count,
            'total_spots': 3,
            'is_full': total_count >= 3
        })
    except Exception as e:
        print(f"Erro ao buscar estado do office: {str(e)}")
        return jsonify({'error': str(e)}), 500

def get_user_data(email):
    print(f"Buscando dados do usuário: {email}")  # Debug
    query = client.query(kind='User')
    query.add_filter('email', '=', email)
    user = list(query.fetch(limit=1))
    
    if not user:
        print(f"Criando novo usuário: {email}")  # Debug
        # Criar novo usuário
        user_key = client.key('User')
        user = datastore.Entity(key=user_key)
        user.update({
            'email': email,
            'name': email.split('@')[0],
            'team': 'default-team',
            'is_team_lead': False,
            'is_admin': email in get_admin_emails(),
            'created_at': datetime.datetime.now()
        })
        client.put(user)
        print(f"Novo usuário criado: {user}")  # Debug
        return user
    
    print(f"Usuário encontrado: {user[0]}")  # Debug
    return user[0]

@app.route('/admin/teams')
@admin_required
def admin_teams():
    # Buscar todas as equipas
    query = client.query(kind='Team')
    teams = list(query.fetch())
    
    # Buscar todos os usuários
    query = client.query(kind='User')
    users = list(query.fetch())
    
    return render_template(
        'admin_teams.html',
        teams=teams,
        users=users
    )

@app.route('/admin/team/create', methods=['POST'])
@admin_required
def create_team():
    try:
        name = request.form.get('name')
        team_lead = request.form.get('team_lead')
        
        team_key = client.key('Team')
        team = datastore.Entity(key=team_key)
        team.update({
            'name': name,
            'team_lead': team_lead,
            'mandatory_days': [],
            'created_at': datetime.datetime.now()
        })
        client.put(team)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/admin/team/<team_id>')
@admin_required
def get_team(team_id):
    team_key = client.key('Team', team_id)
    team = client.get(team_key)
    if not team:
        return jsonify({'error': 'Equipa não encontrada'}), 404
    return jsonify(team)

@app.route('/admin/team/update', methods=['POST'])
@admin_required
def update_team():
    try:
        data = request.get_json()
        team_id = data.get('id')
        team_key = client.key('Team', team_id)
        team = client.get(team_key)
        
        if not team:
            return jsonify({'error': 'Equipa não encontrada'}), 404
            
        team.update({
            'name': data.get('name'),
            'team_lead': data.get('team_lead'),
            'updated_at': datetime.datetime.now()
        })
        client.put(team)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)})

def count_user_days(reservations):
    """Conta os dias de reserva de um usuário"""
    return sum(1 if r['type'] == 'full' else 0.5 for r in reservations)

@app.route('/debug/users')
@admin_required
def debug_users():
    query = client.query(kind='User')
    users = list(query.fetch())
    return jsonify([
        {
            'email': user.get('email'),
            'name': user.get('name'),
            'team': user.get('team'),
            'is_admin': user.get('is_admin')
        } 
        for user in users
    ])

@app.route('/debug/all')
@admin_required
def debug_all():
    # Buscar usuários
    user_query = client.query(kind='User')
    users = list(user_query.fetch())
    
    # Buscar reservas
    res_query = client.query(kind='Reservation')
    reservations = list(res_query.fetch())
    
    # Buscar admins
    admin_query = client.query(kind='Admin')
    admins = list(admin_query.fetch())
    
    return jsonify({
        'users': [{
            'email': u.get('email'),
            'name': u.get('name'),
            'team': u.get('team'),
            'is_admin': u.get('is_admin'),
            'key': u.key.id_or_name
        } for u in users],
        
        'reservations': [{
            'user': r.get('user'),
            'date': r.get('date'),
            'type': r.get('type'),
            'status': r.get('status')
        } for r in reservations],
        
        'admins': [{
            'email': a.get('email'),
            'key': a.key.id_or_name
        } for a in admins]
    })

@app.route('/user/calendar/<email>')
@admin_required
def user_calendar(email):
    try:
        period = request.args.get('period', 'current')
        today = datetime.now()
        
        # Determinar período
        if period == 'previous':
            start_date = (today.replace(day=1) - relativedelta(months=1))
        elif period == 'next':
            start_date = (today.replace(day=1) + relativedelta(months=1))
        elif period == 'annual':
            start_date = today.replace(month=1, day=1)
        else:  # current
            start_date = today.replace(day=1)
            
        # Ajustar data final
        if period == 'annual':
            end_date = start_date.replace(month=12, day=31)
        else:
            next_month = start_date + relativedelta(months=1)
            end_date = next_month - relativedelta(days=1)
            
        # Buscar reservas do usuário
        query = client.query(kind='Reservation')
        query.add_filter('user', '=', email)
        query.add_filter('date', '>=', start_date.strftime('%Y-%m-%d'))
        query.add_filter('date', '<=', end_date.strftime('%Y-%m-%d'))
        query.add_filter('status', '=', 'active')
        
        reservations = list(query.fetch())
        
        # Calcular dias totais considerando meio dia
        days_in_month = sum(1.0 if r.get('type') == 'full' else 0.5 
                          for r in reservations 
                          if r['status'] == 'active')
        
        goal_reached = days_in_month >= 10  # Meta de 10 dias por mês
        
        # Formatar dados para o calendário
        calendar_data = {
            'reservations': [
                {
                    'date': res['date'],
                    'type': res.get('type', 'full'),
                    'status': res.get('status', 'active'),
                    'goal_reached': goal_reached
                }
                for res in reservations
            ],
            'period': {
                'start': start_date.strftime('%Y-%m-%d'),
                'end': end_date.strftime('%Y-%m-%d'),
                'days_count': days_in_month  # Adicionar contagem total de dias
            }
        }
        
        return jsonify(calendar_data)
        
    except Exception as e:
        print(f"Erro ao buscar calendário: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)