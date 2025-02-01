from google.cloud import datastore
import datetime

client = datastore.Client()

def create_default_team():
    print("Criando equipa padrão...")
    # Criar equipa padrão para migração
    team_key = client.key('Team', 'default-team')
    team = datastore.Entity(key=team_key)
    team.update({
        'name': 'Equipa Principal',
        'team_lead': None,  # Será atualizado depois
        'mandatory_days': [],
        'created_at': datetime.datetime.now()
    })
    client.put(team)
    print("Equipa padrão criada com sucesso!")
    return team_key

def migrate_users():
    print("Iniciando migração de usuários...")
    # Buscar todos os usuários
    query = client.query(kind='User')
    users = list(query.fetch())
    print(f"Encontrados {len(users)} usuários")
    
    # Criar equipa padrão
    default_team_key = create_default_team()
    
    # Atualizar usuários com a equipa padrão
    for user in users:
        print(f"Atualizando usuário: {user.get('email')}")
        user.update({
            'team': default_team_key.id_or_name,
            'is_team_lead': False  # valor padrão
        })
        client.put(user)
    print("Migração de usuários concluída!")

def migrate_reservations():
    print("Iniciando migração de reservas...")
    # Buscar todas as reservas
    query = client.query(kind='Reservation')
    reservations = list(query.fetch())
    print(f"Encontradas {len(reservations)} reservas")
    
    # Atualizar reservas
    for reservation in reservations:
        print(f"Atualizando reserva para: {reservation.get('user')} em {reservation.get('date')}")
        reservation.update({
            'is_mandatory': False,  # valor padrão
            'team': 'default-team'  # equipa padrão
        })
        client.put(reservation)
    print("Migração de reservas concluída!")

def run_migration():
    print("Iniciando migração completa...")
    try:
        migrate_users()
        migrate_reservations()
        print("Migração concluída com sucesso!")
    except Exception as e:
        print(f"Erro durante a migração: {str(e)}")

if __name__ == "__main__":
    run_migration() 