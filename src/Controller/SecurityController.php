<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\RegistrationType;
use Doctrine\ORM\EntityManagerInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;


class SecurityController extends AbstractController
{
    #[Route('/login', name: 'app_login', methods: ['GET', 'POST'])]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('app_home');
        }

        $error = $authenticationUtils->getLastAuthenticationError();
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', [
            'controller_name' => 'SecurityController',
            'last_username' => $lastUsername,
            'error' => $error
        ]);
    }

    #[Route('/signup', name: 'app_signup', methods: ['GET', 'POST'])]
    public function registration(Request $request, EntityManagerInterface $manager, UserPasswordHasherInterface $passwordEncoder): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('app_home');
        }

        $user = new User();

        $user->setRoles(['ROLE_USER']);
        $user->setOauth('basic');

        $form = $this->createForm(RegistrationType::class, $user);

        $form->handleRequest($request);
        if ($form->isSubmitted()) {
            $pseudo = $form->get('username')->getData();
            $email = $form->get('email')->getData();

            $existingUser = $manager->getRepository(User::class)->findOneBy(['username' => $pseudo]);

            if ($existingUser) {
                $this->addFlash(
                    'error',
                    'Username already exists.'
                );
                return $this->render('security/signup.html.twig', [
                    'form' => $form->createView()
                ]);
            }

            $existingUser = $manager->getRepository(User::class)->findOneBy(['email' => $email]);

            if ($existingUser) {
                $this->addFlash(
                    'error',
                    'Email already exists.'
                );
                return $this->render('security/signup.html.twig', [
                    'form' => $form->createView()
                ]);
            }

            if ($form['password']['first']->getData() !== $form['password']['second']->getData()) {
                $this->addFlash(
                    'error',
                    'Passwords do not match.'
                );
                return $this->render('security/signup.html.twig', [
                    'form' => $form->createView()
                ]);
            }

            if ($form->isValid()) {
                $user = $form->getData();

                // Hash the password
                $user->setPassword(
                    $passwordEncoder->hashPassword(
                        $user,
                        $form->get('password')->getData()
                    )
                );

                if (empty($user->getUsername())) {
                    $user->setPseudo($user->getFirstname());
                }

                $this->addFlash(
                    'success',
                    'Your account has been created. You can now log in.'
                );

                $manager->persist($user);
                $manager->flush();

                return $this->redirectToRoute('app_login');
            }
        }

        return $this->render('security/signup.html.twig', [
            'form' => $form->createView(),
        ]);
    }

    #[Route('/logout', name: 'app_logout', methods: ['GET'])]
    public function logout()
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }

    #[Route('/login/github', name: 'github_connect', methods: ['GET'])]
    public function githubConnect(ClientRegistry $clientRegistry): Response
    {
        $client = $clientRegistry->getClient('github');
        return $client->redirect(['user:email', 'read:user']);
    }

    #[Route('/login/github/check', name: 'github_connect_check', methods: ['GET'])]
    public function githubConnectCheck(ClientRegistry $clientRegistry, EntityManagerInterface $em, TokenStorageInterface $tokenStorage, SessionInterface $session): Response
    {
        $client = $clientRegistry->getClient('github');

        try {
            $user = $client->fetchUser();

            $userData = $user->toArray();

            $fullName = $userData['name'];
            $nameParts = explode(' ', $fullName);

            $firstName = array_shift($nameParts);
            $lastName = implode(' ', $nameParts);

            $userRepository = $em->getRepository(User::class);
            $existingUser = $userRepository->findOneBy(['email' => $userData['email']]);

            if($existingUser) {
                $existingUser->setFirstname($firstName);
                $existingUser->setLastname($lastName);
                $newUser = $existingUser;
            } else {
                $newUser = new User();
                $newUser->setUsername($userData['login']);
                $newUser->setEmail($userData['email']);
                $newUser->setOauth('github');
                $newUser->setRoles(['ROLE_USER']);
                $newUser->setProfilePicture($userData['avatar_url']);
                $newUser->setPassword('github');
                $newUser->setFirstname($firstName);
                $newUser->setLastname($lastName);
            }

            $em->persist($newUser);
            $em->flush();

            $token = new UsernamePasswordToken($newUser, 'main', $newUser->getRoles());

            $tokenStorage->setToken($token);
            $session->set('_security_main', serialize($token));

            return $this->redirectToRoute('app_home');

        } catch (IdentityProviderException $e) {
            var_dump($e->getMessage()); die;
        }
    }

    #[Route('/login/discord', name: 'discord_connect', methods: ['GET'])]
    public function discordConnect(ClientRegistry $clientRegistry): Response
    {
        $client = $clientRegistry->getClient('discord');
        return $client->redirect(['email', 'identify']);
    }

    #[Route('/login/discord/check', name: 'discord_connect_check', methods: ['GET'])]
    public function discordConnectCheck(ClientRegistry $clientRegistry, EntityManagerInterface $em, TokenStorageInterface $tokenStorage, SessionInterface $session): Response
    {
        $client = $clientRegistry->getClient('discord');

        try {
            $user = $client->fetchUser();

            $userData = $user->toArray();

            $fullName = $userData['global_name'];
            $nameParts = explode(' ', $fullName);

            $firstName = array_shift($nameParts);
            $lastName = implode(' ', $nameParts);

            $userRepository = $em->getRepository(User::class);
            $existingUser = $userRepository->findOneBy(['email' => $userData['email']]);

            if($existingUser) {
                $existingUser->setFirstname($firstName);
                $existingUser->setLastname($lastName);
                $newUser = $existingUser;
            } else {
                $newUser = new User();
                $newUser->setUsername($userData['username']);
                $newUser->setEmail($userData['email']);
                $newUser->setOauth('discord');
                $newUser->setRoles(['ROLE_USER']);
                $newUser->setProfilePicture('https://cdn.discordapp.com/avatars/'.$userData['id'].'/'.$userData['avatar'].'.jpg');
                $newUser->setPassword('discord');
                $newUser->setFirstname($firstName);
                $newUser->setLastname($lastName);
            }

            $em->persist($newUser);
            $em->flush();

            $token = new UsernamePasswordToken($newUser, 'main', $newUser->getRoles());

            $tokenStorage->setToken($token);
            $session->set('_security_main', serialize($token));

            return $this->redirectToRoute('app_home');

        } catch (IdentityProviderException $e) {
            var_dump($e->getMessage()); die;
        }
    }

    #[Route('/login/gitlab', name: 'gitlab_connect', methods: ['GET'])]
    public function gitlabConnect(ClientRegistry $clientRegistry): Response
    {
        $client = $clientRegistry->getClient('gitlab');
        return $client->redirect(['read_user']);
    }

    #[Route('/login/gitlab/check', name: 'gitlab_connect_check', methods: ['GET'])]
    public function gitlabConnectCheck(ClientRegistry $clientRegistry, EntityManagerInterface $em, TokenStorageInterface $tokenStorage, SessionInterface $session): Response
    {
        $client = $clientRegistry->getClient('gitlab');

        try {
            $user = $client->fetchUser();

            $userData = $user->toArray();

            $fullName = $userData['name'];
            $nameParts = explode(' ', $fullName);

            $firstName = array_shift($nameParts);
            $lastName = implode(' ', $nameParts);

            $userRepository = $em->getRepository(User::class);
            $existingUser = $userRepository->findOneBy(['email' => $userData['email']]);

            if($existingUser) {
                $existingUser->setFirstname($firstName);
                $existingUser->setLastname($lastName);
                $newUser = $existingUser;
            } else {
                $newUser = new User();
                $newUser->setUsername($userData['username']);
                $newUser->setEmail($userData['email']);
                $newUser->setOauth('gitlab');
                $newUser->setRoles(['ROLE_USER']);
                $newUser->setProfilePicture($userData['avatar_url']);
                $newUser->setPassword('gitlab');
                $newUser->setFirstname($firstName);
                $newUser->setLastname($lastName);
            }

            $em->persist($newUser);
            $em->flush();

            $token = new UsernamePasswordToken($newUser, 'main', $newUser->getRoles());

            $tokenStorage->setToken($token);
            $session->set('_security_main', serialize($token));

            return $this->redirectToRoute('app_home');

        } catch (IdentityProviderException $e) {
            var_dump($e->getMessage()); die;
        }
    }

    #[Route('/login/google', name: 'google_connect', methods: ['GET'])]
    public function googleConnect(ClientRegistry $clientRegistry): Response
    {
        $client = $clientRegistry->getClient('google');
        return $client->redirect(['email', 'profile']);
    }

    #[Route('/login/google/check', name: 'google_connect_check', methods: ['GET'])]
    public function googleConnectCheck(ClientRegistry $clientRegistry, EntityManagerInterface $em, TokenStorageInterface $tokenStorage, SessionInterface $session): Response
    {
        $client = $clientRegistry->getClient('google');

        try {
            $user = $client->fetchUser();

            $userData = $user->toArray();

            $fullName = $userData['name'];
            $nameParts = explode(' ', $fullName);

            $firstName = array_shift($nameParts);
            $lastName = implode(' ', $nameParts);

            $userRepository = $em->getRepository(User::class);
            $existingUser = $userRepository->findOneBy(['email' => $userData['email']]);

            if($existingUser) {
                $existingUser->setFirstname($firstName);
                $existingUser->setLastname($lastName);
                $newUser = $existingUser;
            } else {
                $newUser = new User();
                $newUser->setUsername($userData['given_name']);
                $newUser->setEmail($userData['email']);
                $newUser->setOauth('google');
                $newUser->setRoles(['ROLE_USER']);
                $newUser->setProfilePicture($userData['picture']);
                $newUser->setPassword('google');
                $newUser->setFirstname($firstName);
                $newUser->setLastname($lastName);
            }

            $em->persist($newUser);
            $em->flush();

            $token = new UsernamePasswordToken($newUser, 'main', $newUser->getRoles());

            $tokenStorage->setToken($token);
            $session->set('_security_main', serialize($token));

            return $this->redirectToRoute('app_home');

        } catch (IdentityProviderException $e) {
            var_dump($e->getMessage()); die;
        }
    }
}
