from google.cloud import datastore
import datetime

client = datastore.Client()

def create_users_from_reservations():
    print("Criando usuários a partir das reservas...")
    
    # Buscar todas as reservas
    query = client.query(kind='Reservation')
    reservations = list(query.fetch())
    
    # Coletar emails únicos
    unique_emails = set()
    for res in reservations:
        if res.get('user'):
            unique_emails.add(res['user'])
    
    print(f"Encontrados {len(unique_emails)} usuários únicos")
    
    # Criar usuários
    for email in unique_emails:
        # Verificar se usuário já existe
        query = client.query(kind='User')
        query.add_filter('email', '=', email)
        existing_user = list(query.fetch(limit=1))
        
        if not existing_user:
            print(f"Criando usuário: {email}")
            user_key = client.key('User')
            user = datastore.Entity(key=user_key)
            user.update({
                'email': email,
                'name': email.split('@')[0],
                'team': 'default-team',
                'is_admin': email in ['andre.c.batista8@gmail.com', 'andre.batista@wisepirates.com'],
                'created_at': datetime.datetime.now()
            })
            client.put(user)
        else:
            print(f"Usuário já existe: {email}")

if __name__ == "__main__":
    create_users_from_reservations() 