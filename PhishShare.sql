-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 28, 2025 at 09:33 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `phishsharedb`
--

-- --------------------------------------------------------

--
-- Table structure for table `ai_analysis`
--

CREATE TABLE `ai_analysis` (
  `id` int(11) NOT NULL,
  `submission_id` int(11) NOT NULL,
  `phishing_chance` varchar(20) DEFAULT NULL,
  `reason_1` text DEFAULT NULL,
  `reason_2` text DEFAULT NULL,
  `reason_3` text DEFAULT NULL,
  `recommendation` text DEFAULT NULL,
  `analyzed_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `ai_analysis`
--

INSERT INTO `ai_analysis` (`id`, `submission_id`, `phishing_chance`, `reason_1`, `reason_2`, `reason_3`, `recommendation`, `analyzed_at`) VALUES
(2, 2, 'High', 'The sender\'s email address is incomplete and lacks a proper domain, which raises suspicion about its authenticity.', 'The subject line and body of the email contain nonsensical text, indicating a lack of professionalism and potential phishing intent.', 'There are no specific details or context provided, which is common in phishing attempts that aim to elicit a response without providing legitimate information.', 'Do not engage with this email and consider reporting it as phishing.', '2025-05-28 15:20:19'),
(3, 3, 'High', 'The sender\'s email address is suspicious and does not appear to be from a legitimate domain.', 'The subject line is missing, which is unusual for legitimate emails and can indicate a phishing attempt.', 'The body of the email contains random characters and lacks coherent content, suggesting it may be a phishing attempt.', 'Do not engage with this email and consider marking it as spam.', '2025-05-28 15:22:29');

-- --------------------------------------------------------

--
-- Table structure for table `comments_ratings`
--

CREATE TABLE `comments_ratings` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `email_submission_id` int(11) NOT NULL,
  `rating` int(11) DEFAULT NULL CHECK (`rating` >= 1 and `rating` <= 5),
  `comment` text DEFAULT NULL,
  `timestamp` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `comments_ratings`
--

INSERT INTO `comments_ratings` (`id`, `user_id`, `email_submission_id`, `rating`, `comment`, `timestamp`) VALUES
(2, 2, 2, 1, '', '2025-05-28 15:21:59');

-- --------------------------------------------------------

--
-- Table structure for table `email_submissions`
--

CREATE TABLE `email_submissions` (
  `id` int(11) NOT NULL,
  `email_sender` varchar(255) NOT NULL,
  `email_subject` text DEFAULT NULL,
  `email_body` text NOT NULL,
  `date_submitted` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `email_submissions`
--

INSERT INTO `email_submissions` (`id`, `email_sender`, `email_subject`, `email_body`, `date_submitted`) VALUES
(2, 'tete@ufhsd', 'tete', 'tetetetet', '2025-05-28 15:20:12'),
(3, 'ttsqrhfnvisqfmaodrfc@madaseraroche.baby', '', 'nfuienfbewubfwebfw', '2025-05-28 15:22:26');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `date_created` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `password_hash`, `date_created`) VALUES
(1, 'test123', 'test@gmail.com', 'scrypt:32768:8:1$x7wCCYFPMdWkm6B0$c2b175b4c7beb10b8f3bd0044df61f70fbb43cb0549b0c0b52169c9b648d67564546c279940e89774de45688c4baeb36e0cfd3b338fbfe8573851feea9e9ad0b', '2025-05-26 19:53:17'),
(2, 'test', 'test2@test', 'scrypt:32768:8:1$fRhXR1GQlT4C7YSD$4eb220af29f5407972a3a5c54754918412687acb5609ba7e1e51aa0f4d3530cf308b2d68d426d93fe4f8896cf223107143e2a30c6dd6755b423ae3ec69fe70b7', '2025-05-27 19:50:29');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `ai_analysis`
--
ALTER TABLE `ai_analysis`
  ADD PRIMARY KEY (`id`),
  ADD KEY `submission_id` (`submission_id`);

--
-- Indexes for table `comments_ratings`
--
ALTER TABLE `comments_ratings`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `email_submission_id` (`email_submission_id`);

--
-- Indexes for table `email_submissions`
--
ALTER TABLE `email_submissions`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `ai_analysis`
--
ALTER TABLE `ai_analysis`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `comments_ratings`
--
ALTER TABLE `comments_ratings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `email_submissions`
--
ALTER TABLE `email_submissions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `ai_analysis`
--
ALTER TABLE `ai_analysis`
  ADD CONSTRAINT `ai_analysis_ibfk_1` FOREIGN KEY (`submission_id`) REFERENCES `email_submissions` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `comments_ratings`
--
ALTER TABLE `comments_ratings`
  ADD CONSTRAINT `comments_ratings_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `comments_ratings_ibfk_2` FOREIGN KEY (`email_submission_id`) REFERENCES `email_submissions` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
