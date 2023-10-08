<!DOCTYPE html>
<html>
<head>
    <title>Hasil Pengecekan Nama</title>
</head>
<body>
    <h1>Hasil Pengecekan Nama</h1>
    
    <table>
        <tr>
            <th>Nama</th>
            <th>Status</th>
        </tr>
        <?php foreach ($hasil as $nama => $status): ?>
        <tr>
            <td><?= $nama ?></td>
            <td><?= $status ?></td>
        </tr>
        <?php endforeach; ?>
    </table>

    <br>
    <a href="/">Kembali ke Form</a>
</body>
</html>
