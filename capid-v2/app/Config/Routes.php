<?php

use CodeIgniter\Router\RouteCollection;

/**
 * @var RouteCollection $routes
 */
$routes->get('/', 'Home::index');
$routes->get('/', 'NamaOrangController::index'); // Rute untuk halaman formulir
$routes->post('/cek-nama', 'NamaOrangController::cekNama'); // Rute untuk memproses unggahan PDF dan menampilkan hasil

