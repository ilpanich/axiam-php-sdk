<?php

declare(strict_types=1);

// examples/symfony_app/DocumentController.php — the CONTRACT.md §11 declarative
// authorization helpers half of the SC#4-Symfony example: `#[RequireAccess]` on a
// controller method, enforced by `Axiam\Sdk\Symfony\AxiamAccessAttributeListener` (a
// `kernel.controller` listener — see `services.yaml` in this directory, which tags it
// exactly like `AxiamAuthSubscriber`/`AxiamVoter`). This is the SAME attribute class
// the Laravel bridge's `#[RequireAccess]`-attributed `DocumentApiController` in
// `../laravel_app/routes.php` uses — one attribute, both frameworks.
//
// This directory ships as illustrative, `php -l`-clean source (the core
// `axiam/axiam-sdk` package intentionally has zero `symfony/*` RUNTIME dependency,
// D-01 — it does not bundle a bootable Symfony kernel), same as `../symfony_app`'s
// README shows for the plain `AxiamVoter`-based controller.

namespace App\Controller;

use Axiam\Sdk\Attributes\RequireAccess;
use Axiam\Sdk\Attributes\RequireAuth;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Illustrative controller demonstrating CONTRACT.md §11's `#[RequireAuth]`/
 * `#[RequireAccess]` declarative helpers, as an alternative to this example's sibling
 * `README.md` controller (which calls `denyAccessUnlessGranted()`/`AxiamVoter`
 * directly). Both styles are equally valid — this one needs no `security.yaml` access
 * control rules or manual `denyAccessUnlessGranted()` call in the method body at all;
 * `AxiamAccessAttributeListener` (registered in `services.yaml`) enforces the
 * attribute before the method ever runs.
 */
final class DocumentController extends AbstractController
{
    /**
     * `GET /documents/{id}` — requires an authenticated identity (`#[RequireAuth]` is
     * redundant here since `#[RequireAccess]` already implies it, CONTRACT.md §11.2.1,
     * but is shown for endpoints that only need `require_auth` with no resource check
     * at all) AND a `read` authorization check on the resource UUID resolved from the
     * `{id}` route parameter (`resourceParam: 'id'`, the default).
     */
    #[Route('/documents/{id}', methods: ['GET'])]
    #[RequireAuth]
    #[RequireAccess(action: 'read', resourceParam: 'id')]
    public function show(string $id): JsonResponse
    {
        // If this line is reached at all: AxiamAuthSubscriber (kernel.request)
        // already verified the token, AND AxiamAccessAttributeListener
        // (kernel.controller) already confirmed `checkAccess('read', $id)` for the
        // REQUEST's authenticated user — no manual check needed in this method body.
        return $this->json(['id' => $id, 'title' => 'Q3 Compliance Report']);
    }
}
