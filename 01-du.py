import requests
import base64
import click
import configparser
import pprint
import time


def twitter_session(api_key, api_secret):
    session = requests.Session()
    secret = '{}:{}'.format(api_key, api_secret)
    secret64 = base64.b64encode(secret.encode('ascii')).decode('ascii')

    headers = {
        'Authorization': 'Basic {}'.format(secret64),
        'Host': 'api.twitter.com',
    }

    r = session.post(
        'https://api.twitter.com/oauth2/token',
        headers=headers,
        data={'grant_type': 'client_credentials'})


    bearer_token = r.json()['access_token']

    def bearer_auth(req):
        req.headers['Authorization'] = 'Bearer ' + bearer_token
        return req

    session.auth = bearer_auth

    return session

@click.command()
@click.option('--cesta', default='auth.cfg', help='Zadej cestu k souboru s hesly, napr. auth.cfg.')
@click.option('--hledani', default='#python', help='Zadej hledane slovo (hastagy dej do uvozovek), napr. #python.')
@click.option('--pocet', default=10, help='Zadej pocet tweetu, napr. 5')
#@click.option('--preposlani', default="original", help='Nastav retweety na original nebo preposlano.')
def prihlaseni(cesta, hledani, pocet):
    config = configparser.ConfigParser()
    config.read(cesta) 
    api_key = config['twitter']['key']
    api_secret = config['twitter']['secret']

    session = twitter_session(api_key, api_secret)


    r = session.get(
        'https://api.twitter.com/1.1/search/tweets.json',
        params={'q': hledani, 'count':pocet},
    )

    #pprint.pprint(r.json)
    nejnovejsi_prispevek = 0
    for tweet in r.json()['statuses']:
        print(tweet['text'])
        print("-"*20)
        if nejnovejsi_prispevek < tweet['id']:
            nejnovejsi_prispevek = tweet['id']
    opakovane_vytvoreni_session(session, hledani, nejnovejsi_prispevek)




def opakovane_vytvoreni_session(session,hledani, nejnovejsi_prispevek):
    time.sleep(5)
    print("Nove hledani.")

    r = session.get(
        'https://api.twitter.com/1.1/search/tweets.json',
        params={'q': hledani},
    )

    for tweet in r.json()['statuses']:
        if  tweet['id'] > nejnovejsi_prispevek:
            print(tweet['text'])
            print("-"*20)
            nejnovejsi_prispevek = tweet['id']
    opakovane_vytvoreni_session(session,hledani, nejnovejsi_prispevek)

if __name__ == '__main__':
    prihlaseni()
