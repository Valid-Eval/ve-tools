# ve-tools

## setup

You are going to want to create a virtualenv for ve-tools.  This documents how to do that with pyenv

### Pyenv
[pyenv](https://github.com/pyenv/pyenv)
This lets you have multiple python installations, gets you off of the system python and makes dealing with virtualenvs easier.  You will also get the active virtualenv in your prompt

#### Ubuntu
```zsh
sudo apt install wget build-essential libreadline-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev lzma lzma-dev liblzma-dev
curl https://pyenv.run | bash
#pyenv install -l | less # Look for the lastest stable 3.x.  At time of writing 3.10.10
pyenv install 3.11
pyenv global 3.11
```

#### RHEL
```
sudo dnf install -y \
        make \
        gcc \
        zlib-devel \
        bzip2 \
        bzip2-devel \
        readline-devel \
        sqlite \
        sqlite-devel \
        openssl-devel \
        tk-devel \
        libffi-devel \
        git

curl https://pyenv.run | bash
pyenv install 3.11
pyenv global 3.11
```

Restart your shell.
### pyenv-virtualenv
[pyenv-virtualenv](https://github.com/pyenv/pyenv-virtualenv)
[pyenv-virtualenvwrapper](https://github.com/pyenv/pyenv-virtualenvwrapper)
Allows every python program to have a completely isolated environment, so no library leakage from app to app.

```
pip install virtualenv # You neeed to do this inside each python you install above


git clone https://github.com/pyenv/pyenv-virtualenvwrapper.git $(pyenv root)/plugins/pyenv-virtualenvwrapper

pyenv virtualenv valid-eval
pyenv activate valid-eval
```

add the following to the end of ~/.zshrc

```
pyenv activate valid-eval
```

Restart your shell.

### Creating the ve-tools virtualenv

```pyenv virtualenv ve-tools```

```pyenv activate ve-tools```

Then, from the root of the project

```pip install -r requirements.txt```

## dockercredrot

This tool is designed to automate a part of the docker credentials rotation.  Flux as it is configured is getting the creds from a dockerconfigjson, which is a multi-layered base64 encoded string.  This tool automates creation of that string.

```./dockercredrot <registry name> <username> <email>```

This will ask for the password and then returns the base64 string needed for the config.

## credbridge

Credbridge is a go tool that takes can take a users's aws environment, particularly an sso one and exposed the credentials in a container.  This is designed for local dev use, and credbridge should _never_ be used in a production environment.  To use it, you need to export your AWS_PROFILE into your container and also mount your ~/.aws directory to the container's user's home directory.  You can then use this to pass credentials to applications that are sso unaware like this:

```
export AWS_ACCESS_KEY_ID="$(credbridge access)"
export AWS_SECRET_ACCESS_KEY="$(credbridge secret)"
export AWS_SESSION_TOKEN="$(credbridge token)"
export AWS_CREDENTIAL_EXPIRATION="$(credbridge expires)"
```

you can also execute credbridge like this:

```
credbridge >> aws.env
source aws.env
```

The primary use case 

# Python Kube tools

```
pyenv virtualenv ve-tools
pyenv activate ve-tools
pip install setuptools==66.1.1
./setup.py install```

You can:

1) Symlink the binaries to your bin directory

`ln -s ~/.pyenv/versions/ve-tools/bin/kubectl-ve-queues ~/bin/kubectl-ve-queues`

`ln -s ~/.pyenv/versions/ve-tools/bin/kubectl-ve-console ~/bin/kubectl-ve-console`

and add your bin directory to your PATH, but this must be done later in your shell profile than pyenv
`echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc`

2) Add the ve-tools virtualenv bin to your path
`export PATH="$HOME/.pyenv/versions/ve-tools/bin:$PATH"`

3) Activate the ve-tools virtualenv in any shell where you want to use these plugins

4) Or instead do the `./setup.py install` in the valid-eval virtualenv (and any others wher you want the tools to work)