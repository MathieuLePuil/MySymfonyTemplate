<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\RegistrationType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
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
}
